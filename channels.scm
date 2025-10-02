(use-modules (guix))

(list (channel (name 'guix)
    (url "https://codeberg.org/guix/guix.git")
    (branch "master")
    (commit "db6d6b00e7a82f91622c3e94de2fac860b6abf79")
    (introduction
      (make-channel-introduction
        "9edb3f66fd807b096b48283debdcddccfea34bad"
        (openpgp-fingerprint
          "BBB0 2DDF 2CEA F6A8 0D1D E643 A2A0 6DF2 A33A 54FA")))))
