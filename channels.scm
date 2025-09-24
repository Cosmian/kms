(use-modules (guix))

(list (channel (name 'kms)
               (url "https://github.com/Cosmian/kms.git")
               (branch "tbz/guix-build"))
      (channel (name 'guix)
               (url "https://git.guix.gnu.org/guix.git")
               (branch "master")
               (commit "d9e2ee3e99475cfa5caa7c9ee7f2f54e3f71215f")
               (introduction
                (make-channel-introduction
                 "9edb3f66fd807b096b48283debdcddccfea34bad"
                 (openpgp-fingerprint
                  "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA")))))
