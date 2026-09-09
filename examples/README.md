Documents signed by a throwaway CA (`TEST CACHET CA`) — not real attestations,
not a real trust anchor. Each page reads `Nom: DUPONT Jean`. Regenerate with
`python3 examples/regenerate.py`.

    A="--anchor examples/test-ca.pem"
    fi-verify examples/signed.pdf          $A                        # 2  no revocation data
    fi-verify examples/signed.pdf          $A --crl examples/test.crl # 0  fully checked
    fi-verify examples/forged-inplace.pdf  $A                        # 1  HASH_FAILURE
    fi-verify examples/forged-append.pdf   $A                        # 1  FORMAT_FAILURE
    fi-verify examples/signed.pdf                                    # 1  chain not trusted

`test.crl` is a CRL from the same throwaway CA, listing nothing. The
certificates point at `crl.example.test`, which does not resolve, so
`--fetch-revocation` will report the download failure rather than a status —
that flag is for real documents.

Both forgeries change the name to `Nom: DURAND Paul` — confirm with
`pdftotext examples/forged-append.pdf -` — but they fail in different places.

`forged-inplace.pdf` edits bytes inside the signed range, keeping the length.
The CMS is intact, so `cms.signature` still passes; `cms.message_digest` fails.

`forged-append.pdf` is how a PDF editor saves an edit: the page content object is
redefined in an incremental update appended *after* the signed range. The seal
still covers its own bytes, so both `cms.signature` and `cms.message_digest`
pass, and `openssl cms -verify` reports the file valid. Only `pdf.coverage`
catches it.
