(define-module (kms)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix deprecation)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix base16)
  #:use-module (guix gexp)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system go)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system pyproject)
  #:use-module (guix build-system python)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system trivial)
  #:use-module (guix build-system meson)
  #:use-module ((guix search-paths) #:select ($SSL_CERT_DIR $SSL_CERT_FILE))
  #:use-module (gnu packages compression)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages build-tools)
  #:use-module (gnu packages check)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages dns)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages libbsd)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages libunistring)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages nettle)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages nss)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-build)
  #:use-module (gnu packages python-crypto)
  #:use-module (gnu packages python-web)
  #:use-module (gnu packages python-xyz)
  #:use-module (gnu packages sphinx)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages time)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages base)
  #:use-module (gnu packages tls)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (guix profiles))

(define-public openssl-3.1.2
  (package
    (inherit openssl-3.0)
    (version "3.1.2")
    (source (origin
        (method url-fetch)
        (uri (list
            (string-append
              "https://github.com/openssl/openssl/releases/download/openssl-"
              version
              "/openssl-"
              version
              ".tar.gz")))
        (sha256
          (base16-string->bytevector
            ;; Value found on the OpenSSL website.
            "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539"))))
    (arguments
      (substitute-keyword-arguments
        (package-arguments openssl-3.0)
        ((#:disallowed-references refs #~ '()) '())
        ((#:configure-flags flags #~ '()) #~ (append #$flags
            '("enable-fips" "no-shared" "no-dynamic-engine")))))))

(manifest
  (list
    (manifest-entry
      (name "openssl")
      (version (package-version openssl-3.1.2))
      (item openssl-3.1.2))
    (manifest-entry
      (name "openssl")
      (version (package-version openssl-3.1.2))
      (output "static") (item openssl-3.1.2))))
