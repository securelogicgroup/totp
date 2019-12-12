package totp

import (
	"testing"
	"time"
)

func TestCreateSha1(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 6, 30, SHA1)
	code, _ := myOtp.Create(time.Unix(1558055982, 0))
	expectedCode := "509877"
	if expectedCode != code {
		t.Errorf("Generated code %s is not matching the expected code %s", code, expectedCode)
	}
}

func TestCreateSha1Digits4(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 4, 30, SHA1)
	code, _ := myOtp.Create(time.Unix(1558055982, 0))
	expectedCode := "9877"
	if expectedCode != code {
		t.Errorf("Generated code %s is not matching the expected code %s", code, expectedCode)
	}
}

func TestValidate(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 6, 30, SHA1)

	if !myOtp.Validate("509877", time.Unix(1558055982, 0), time.Duration(0)) {
		t.Errorf("Validation of code failed")
	}
}

func TestURIGoogleAuth(t *testing.T) {
	myOtp := NewTOTP("My1234567123412341234123412341234", 6, 30, SHA1)
	uri := myOtp.URI("TrustGrid", "SecureLogic")
	expectedURI := "otpauth://totp/TrustGrid?secret=JV4TCMRTGQ2TMNZRGIZTIMJSGM2DCMRTGQYTEMZUGEZDGNBRGIZTI&issuer=SecureLogic&algorithm=SHA1"
	if expectedURI != uri {
		t.Errorf("Generated uri %s is not matching the expected uri %s", uri, expectedURI)
	}
}

func TestURISha1(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 6, 30, SHA1)
	uri := myOtp.URI("TrustGrid", "SecureLogic")
	expectedURI := "otpauth://totp/TrustGrid?secret=JV4VGZLDOJSXITLZKNSWG4TFORGXSU3FMNZGK5CNPFJWKY3SMV2A&issuer=SecureLogic&algorithm=SHA1"
	if expectedURI != uri {
		t.Errorf("Generated uri %s is not matching the expected uri %s", uri, expectedURI)
	}

}

func TestURIAdminUser(t *testing.T) {
	myOtp := NewTOTP("trustgridadmin", 6, 30, SHA1)
	uri := myOtp.URI("TrustGrid", "SecureLogic")
	expectedURI := "otpauth://totp/TrustGrid?secret=ORZHK43UM5ZGSZDBMRWWS3Q&issuer=SecureLogic&algorithm=SHA1"
	if expectedURI != uri {
		t.Errorf("Generated uri %s is not matching the expected uri %s", uri, expectedURI)
	}

}

func TestURISha256(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 6, 30, SHA256)
	uri := myOtp.URI("TrustGrid", "SecureLogic")
	expectedURI := "otpauth://totp/TrustGrid?secret=JV4VGZLDOJSXITLZKNSWG4TFORGXSU3FMNZGK5CNPFJWKY3SMV2A&issuer=SecureLogic&algorithm=SHA256"
	if expectedURI != uri {
		t.Errorf("Generated uri %s is not matching the expected uri %s", uri, expectedURI)
	}
}

func TestURISha512(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 6, 30, SHA512)
	uri := myOtp.URI("TrustGrid", "SecureLogic")
	expectedURI := "otpauth://totp/TrustGrid?secret=JV4VGZLDOJSXITLZKNSWG4TFORGXSU3FMNZGK5CNPFJWKY3SMV2A&issuer=SecureLogic&algorithm=SHA512"
	if expectedURI != uri {
		t.Errorf("Generated uri %s is not matching the expected uri %s", uri, expectedURI)
	}
}

func TestURIPeriodIntervalSha1(t *testing.T) {
	myOtp := NewTOTP("MySecretMySecretMySecretMySecret", 4, 60, SHA1)
	uri := myOtp.URI("TrustGrid", "SecureLogic")
	expectedURI := "otpauth://totp/TrustGrid?secret=JV4VGZLDOJSXITLZKNSWG4TFORGXSU3FMNZGK5CNPFJWKY3SMV2A&issuer=SecureLogic&algorithm=SHA1&digits=4&period=60"
	if expectedURI != uri {
		t.Errorf("Generated uri %s is not matching the expected uri %s", uri, expectedURI)
	}
}
