package security

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"testing"
)

const (
	csr = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBoTCCAQoCAQAwEzERMA8GA1UEChMISnVqdSBvcmcwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBANFf06eqiDx0+qD/xBAR5aMwwgaBOn6TPfSy96vOxLTsfkTg
ir/vb8UG+F5hO6yxF+z2BgzD8LwcbKnxahoPq/aWGLw3Umcqm4wxgWKHxvtYSQDG
w4zpmKOqgkagxbx32JXDlMpi6adUVHNvB838CiUys6IkVB0obGHnre8zmCLdAgMB
AAGgTjBMBgkqhkiG9w0BCQ4xPzA9MDsGA1UdEQQ0MDKGMHNwaWZmZTovL3Rlc3Qu
Y29tL25hbWVzcGFjZS9ucy9zZXJ2aWNlYWNjb3VudC9zYTANBgkqhkiG9w0BAQsF
AAOBgQCw9dL6xRQSjdYKt7exqlTJliuNEhw/xDVGlNUbDZnT0uL3zXI//Z8tsejn
8IFzrDtm0Z2j4BmBzNMvYBKL/4JPZ8DFywOyQqTYnGtHIkt41CNjGfqJRk8pIqVC
hKldzzeCKNgztEvsUKVqltFZ3ZYnkj/8/Cg8zUtTkOhHOjvuig==
-----END CERTIFICATE REQUEST-----`

	keyRSA = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAw/OBAAhDu58f0HkJlJBtb42Jp9EECC+WYEOVEdM/Y9fqcoSF
b19NxztVqy0r/aW8pCO3DZ2EYIA3Y9pYasDfhsIl9lhQkvEwk/05iL6oNrZ45Bgs
iSK+R5OlO9pXtj6HF948qFTDYbYVqki3rAWSSYeGpQ+/s/xcIIIKH5ozKs7DTqR8
svQ6t7Hxg0vYSUCHfJo25yIvoo8XGZxrFWOZDXfHHC22q8kuuxT82bdQo7KzYhgn
uujyzIZYqgG9BuUmB6UYdvuDRRDz4HDfERSFFxZbTAaMPNgCRvQnkPS0DJO0XZW2
T9m3bQvaqTgFI/capuhhgRcP0UrStJKZO7LVHQIDAQABAoIBAFLw0v2Mgf78j57S
XLfBmlDJfCbIVgiQ+/mrIYH2BLLiRZ5LcZ9+m5FlEBHwgNpQONTROT5OGiYun0No
vFwTX4nOy/rFzvUjmghJ+vxilxjxi6IgiVlSl2/8ksgO12mQdeYob0xg9IJ7bBgz
x2rMwOrWrqtXSzGH9AbehCJ0RowrUUjTujnow8WrDVS0cjPIl9c1eQDIDlHCUskC
iGMYYfJtB1nkdw1Kkp1YVmCYqwzVENi6+Hx66j/oOtGteTelwFmclc7JIK7liKEZ
xnDbgVTkIp9nSszpHStWikwh/srCWI7trC/k0viViZQLOd/64CyJ/sf8uZDzsG7f
hoiK3pECgYEAxF/d7QcDWaXCBkw4yC8ozqp6KTcA8thVuBK0Adtpzuf9t8h+B7V2
wlkSEs4A3YiUnxolEh1XOT+0u3uGfawlhFgXxEEHeBq+Lz6PIbWuVSl4PiWo8vtj
9MoBYRPtJelhHkBfjunqqaFwdRQQvXjmCsQfx4UAhBxdXvc2kTR/y08CgYEA/3K8
DKXldQliScqkG+Acj6nNgugecLYjCHgmAglHX6jwDuTVqNF3cv3DF5bZ4/nIbDsk
WooVhS4AEFYWceqmTveGsJNuDMoRSWNwDFRBu5Iq6LxneKiXp9vuZ4U4xZNejrgx
la7w1hQs92qCloY4Jxw9Ls3zKub4vC26CfJwzdMCgYBGw0T1ZNGQPGruWgkcGeJa
lpPuxiNRXyOEcTjscmRuaqrCzzybCokA/5fDrvgg3Fax/nndTTVhK9O0u457Os1K
I3RtBAHtBbYC0EhDnXR0u7zYqDl5VZ1vWFum38dVIgQdIpVMqn4lIkej6Ncfb7F1
r7bD7umAsbfzwKGpMYHbgQKBgQDL03vzR6hIc71mjffWekOv6lieXKJ1Yw+fIWeK
dmbqEH3EFJnbg5AhRBSYTPj9bICcw7AlQksbonHQlzB/ozEij2V8nZbRQ6b5fQuZ
+t0cUuxEGpkhcLzZ5qZbGbUMCaQIkzaVbiqjVyPuI6Ghg+VoZ6L2JsUh9XyBgqcQ
as/RmwKBgGPB8PHYHyz0km8LxM/GPstcoO4Ls5coS3MX2EBDKGqWOIOtLKz0azc7
R4beF5BJE6ulhLig4fkOWH4CIvw2Y1/22GJE/fYjUTRMD57ZdYuKqSyMNxwqiolw
xGSDfnFvR13RCqeUdlQofVYpolqrSobOyOVfQv2ksnPPsC87NISM
-----END RSA PRIVATE KEY-----`

	keyInvalidRSA = `
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----`

	keyECDSA = `
-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHBMUyVWFKTW4TwtwCmIAxdpsBFn0MV7tGeSA32CgBwYFK4EEACGhPAM6
AATCkAx7whb2k3xWm+UjlFWFiV11oYmIdYgXqiAQkiz7fEq6QFhsjjCizeGzAlhT
TmngRSxv/dSvGA==
-----END EC PRIVATE KEY-----`

	keyInvalidECDSA = `
-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----`

	keyInvalidPKCS8 = `
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`

	certRSA = `
-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIQQ0vFSayWg4FQBBr1EpI5rzANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQKEwhKdWp1IG9yZzAeFw0xNzAzMTEwNjA0MDJaFw0xODAzMTEwNjA0
MDJaMBMxETAPBgNVBAoTCEp1anUgb3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAw/OBAAhDu58f0HkJlJBtb42Jp9EECC+WYEOVEdM/Y9fqcoSFb19N
xztVqy0r/aW8pCO3DZ2EYIA3Y9pYasDfhsIl9lhQkvEwk/05iL6oNrZ45BgsiSK+
R5OlO9pXtj6HF948qFTDYbYVqki3rAWSSYeGpQ+/s/xcIIIKH5ozKs7DTqR8svQ6
t7Hxg0vYSUCHfJo25yIvoo8XGZxrFWOZDXfHHC22q8kuuxT82bdQo7KzYhgnuujy
zIZYqgG9BuUmB6UYdvuDRRDz4HDfERSFFxZbTAaMPNgCRvQnkPS0DJO0XZW2T9m3
bQvaqTgFI/capuhhgRcP0UrStJKZO7LVHQIDAQABo0swSTAOBgNVHQ8BAf8EBAMC
BaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAUBgNVHREEDTAL
gglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAITDuqOhN1jwiA72qSWzOwuy
bMHPkUTUw2JfICtPS0AlfNNVJXREUi4KoX81ju126PGQeOTApWvS5Kkd6PbNqVH9
g3myAKrkyjewTfFtK5OOOQGzQT6lCEhKdZJusdqfAMl1heFJGnZ6GAi38ftdz2Z8
0LPyyIaVBvexNnTPrqoBqdtWyzjYIdMnsSNWJnldmWjwA76sW+vvlLvTONiT4unM
8ia4GGIw7GK4E/7qxl27q6pXdZkZgG53XItYiUJGAKeBJ2nQfXq0qSmtpHkF17Cu
hw25X3FJpzRq62JxTx5q6+M2c07g4dkbfMDp/TO7vF4SWruU6JBZj5MVDYn4PEA=
-----END CERTIFICATE-----`

	certECDSA = `
-----BEGIN CERTIFICATE-----
MIIBSzCB+qADAgECAhAzJszEACNBOHrsfSUJMPsHMAoGCCqGSM49BAMCMAsxCTAH
BgNVBAoTADAeFw0xNzAzMTMwNTE2NThaFw0xNzAzMTMwNTE2NThaMAsxCTAHBgNV
BAoTADBOMBAGByqGSM49AgEGBSuBBAAhAzoABMKQDHvCFvaTfFab5SOUVYWJXXWh
iYh1iBeqIBCSLPt8SrpAWGyOMKLN4bMCWFNOaeBFLG/91K8Yo0swSTAOBgNVHQ8B
Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAUBgNV
HREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDQAAwPQIcY8lgBAAtFWtxmk9k
BB6nORpwdv4LVt/BFgLwWQIdAKvHn7cxBJ+aAC25rIumRNKDzP7PkV0HDbxtX+M=
-----END CERTIFICATE-----`

	pkcs8Key = `
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDQtOSXl7nU2Mc7
oXJTcKtg3m1ixKhdvMW7qOcXGLGipn65v+FZHS0nHwKOUsarXaAvSqZADYg0ulXg
KNBoI1iXol7yRdN8EZ100IfJVERH5iCOV5zWEHawCwk6/12aLibR9S1yoamnJQfH
xlSybJ2uQxJCK2oTVLwhHDjV5WzYEdiYuby30si+AFlf5PmEo9uD2sk33Rw3eTfC
/DuxSmfZBeTK4JxE+vvknW9+WJK1k3ZQPCUW35SNR3yemJw2IqmbuTjmEewDBO6y
95Xymic4pwIumcJyD4BT+ndkIX0BxPndEzimSq42QyvZyRuWQQ8aCTULLLjDyiyK
IlpO7DnPAgMBAAECggEBANAM86+Wpb5jl0B/cYtyTrVTJfIGntxK2UZ4Wl2w1SuS
E9QxToBaUG+mPxMHu1qLC6r5HH/PvY7qjb7WkOKvEZqfV0zmhKsymCch1arCYQrX
gm7DMepHITne1oXEmVegWDyGz5ZtR8UCah4hPL9c/VcBL4tc4fKBTsUm8BVyDq3Y
Vl6w9AZNFVjYObrY64rX3Gg95Z5hIKaC/gIwP+hFOvBcG7y+uUMmzXL8DtH36unN
zpGTv6FQFYnvhQMhCDufp8ez2ilQq/9E233dXYTdThlp59z6TtY8lE3ustD/iUjg
uDHRkkS+puunrVhfyEye0ZILcOnwXygtLrjtSck17ikCgYEA+MJnaOaTbuEDmj8K
5mm1werXWUAm9ruSLYHx54xfEqOQSCgV3rIPagBky9922pTkb2/skHXG/Ui8hiCO
LA1/dFKfEi1bSA2ORyWB/8SKsONFFs0klKA9p926XQoNsmYeTfrkuOHyaI0AyX9K
5ANrSmz6mKbmJ4mJUrKXf1yHvK0CgYEA1sgKkaN/m6vBwE+59f/cBN5PoB3+Dgl8
xqO3FmPyqt93tDbR0TvJuzGCBZRMgcJs033HXFb1glLASD3a/s416Fsj9rcahKBu
tW3Zar0LIufbNTq1+uV/L7qe2XltizJ1bmFkmgEJ9EfIuu9gT/P0bAg1l6YY/aKE
ALeQPIsMA+sCgYAnLO5+LbnQP22C0CTWTpWKOYK6kojQWI/XzNwc3BVo6Qti4bU4
AhC9X9x/4uxj1gj3p8e4pGO3JcpS0TOyqlmFJzHX+f6jJUdf2v9TGU/CNbh+s8Xs
BiRPmHKuDlRD4SMqorV8jFDRuEsEcKCJsiQmb20zty0N0vImbOvA6gCSbQKBgQCK
aITvD3a3YbrM7FPBJG2rsXuMimdislh3RZ9BzYze8n0YZE9Xz3iTqjbI06Vt5VXu
AFsNtXgm0J7arwnGNCrnHnyRi7OKDjzpq+107HgVuWY46inFkkkg/9lH+glOr2if
hiGnYM4CXpQLayEcxPAZAj1PCZmHMUhxkdlgOpa2mwKBgQDzJN9xhQlYC1ucC5wE
gGJvNUR3YubkrrOx2S35Ayat7Lzz+TB4m349oh3ZzNdmqZ2ln1LFPqUQyeA5JiW8
AMQLn8TmQGEu9O6qYf+RXRfv4fyw05zm4VcaCtGCEqvIoltBR2RtuWT1qmM9Q3dI
IrzxmKWU9xF9hk3XQqud/iJJzQ==
-----END PRIVATE KEY-----`
)

func TestParsePemEncodedCertificate(t *testing.T) {
	testCases := map[string]struct {
		errMsg        string
		pem           string
		publicKeyAlgo x509.PublicKeyAlgorithm
	}{
		"Invalid PEM string": {
			errMsg: "invalid PEM encoded certificate",
			pem:    "invalid pem string",
		},
		"Invalid certificate string": {
			errMsg: "failed to parse X.509 certificate",
			pem:    keyECDSA,
		},
		"Parse RSA certificate": {
			publicKeyAlgo: x509.RSA,
			pem:           certRSA,
		},
		"Parse ECDSA certificate": {
			publicKeyAlgo: x509.ECDSA,
			pem:           certECDSA,
		},
	}

	for id, c := range testCases {
		cert, err := ParsePemEncodedCertificate([]byte(c.pem))
		if c.errMsg != "" {
			if err == nil {
				t.Errorf("%s: no error is returned", id)
			} else if c.errMsg != err.Error() {
				t.Errorf(`%s: Unexpected error message: expected "%s" but got "%s"`, id, c.errMsg, err.Error())
			}
		} else if cert.PublicKeyAlgorithm != c.publicKeyAlgo {
			t.Errorf("%s: Unexpected public key algorithm: want %d but got %d", id, c.publicKeyAlgo, cert.PublicKeyAlgorithm)
		}
	}
}

func TestParsePemEncodedCSR(t *testing.T) {
	testCases := map[string]struct {
		algo   x509.PublicKeyAlgorithm
		errMsg string
		pem    string
	}{
		"Invalid PEM string": {
			errMsg: "certificate signing request is not properly encoded",
			pem:    "bad pem string",
		},
		"Invalid CSR string": {
			errMsg: "failed to parse X.509 certificate signing request",
			pem:    certECDSA,
		},
		"Parse CSR": {
			algo: x509.RSA,
			pem:  csr,
		},
	}

	for id, c := range testCases {
		_, err := ParsePemEncodedCSR([]byte(c.pem))
		if c.errMsg != "" {
			if err == nil {
				t.Errorf(`%s: no error is returned, expected "%s"`, id, c.errMsg)
			} else if c.errMsg != err.Error() {
				t.Errorf(`%s: Unexpected error message: want "%s" but got "%s"`, id, c.errMsg, err.Error())
			}
		} else if err != nil {
			t.Errorf(`%s: Unexpected error: "%s"`, id, err)
		}
	}
}

func TestParsePemEncodedKey(t *testing.T) {
	testCases := map[string]struct {
		pem     string
		keyType reflect.Type
		errMsg  string
	}{
		"Invalid PEM string": {
			pem:    "Invalid PEM string",
			errMsg: "invalid PEM-encoded key",
		},
		"Parse RSA key": {
			pem:     keyRSA,
			keyType: reflect.TypeOf(&rsa.PrivateKey{}),
		},
		"Parse invalid RSA key": {
			pem:    keyInvalidRSA,
			errMsg: "failed to parse the RSA private key",
		},
		"Parse ECDSA key": {
			pem:     keyECDSA,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
		},
		"Parse invalid ECDSA key": {
			pem:    keyInvalidECDSA,
			errMsg: "failed to parse the ECDSA private key",
		},
		"Parse PKCS8 key using RSA algorithm": {
			pem:     pkcs8Key,
			keyType: reflect.TypeOf(&rsa.PrivateKey{}),
		},
		"Parse invalid PKCS8 key": {
			pem:    keyInvalidPKCS8,
			errMsg: "failed to parse the PKCS8 private key",
		},
	}

	for id, c := range testCases {
		key, err := ParsePemEncodedKey([]byte(c.pem))
		if c.errMsg != "" {
			if err == nil {
				t.Errorf(`%s: no error is returned, expected "%s"`, id, c.errMsg)
			} else if c.errMsg != err.Error() {
				t.Errorf(`%s: Unexpected error message: expected "%s" but got "%s"`, id, c.errMsg, err.Error())
			}
		} else if err != nil {
			t.Errorf(`%s: Unexpected error: "%s"`, id, err)
		} else if keyType := reflect.TypeOf(key); keyType != c.keyType {
			t.Errorf(`%s: Unmatched key type: expected "%v" but got "%v"`, id, c.keyType, keyType)
		}
	}
}

func TestGenCSRTemplate(t *testing.T) {
	tt := map[string]struct {
		host       string
		expectedCN string
	}{
		"Single host": {
			host:       "bla.com",
			expectedCN: "bla.com",
		},
	}

	for _, tc := range tt {
		opts := CertOptions{
			Host:       tc.host,
			Org:        "MyOrg",
			RSAKeySize: 512,
			IsDualUse:  true,
		}

		csr, err := GenCSRTemplate(opts, nil, nil, nil, false)
		if err != nil {
			t.Error(err)
		}

		if csr.Subject.CommonName != tc.expectedCN {
			t.Errorf("unexpected value for 'CommonName' field: want %v but got %v", tc.expectedCN, csr.Subject.CommonName)
		}
	}
}
