#/* SPDX-License-Identifier: MPL-2.0 */
#/**********************************************************************
# * Copyright (c) 2025, Siemens AG
# **********************************************************************/

TEST_DATA_DIR=./test_data

echo "test enroll message flow for the opc ecc profile"

echo "clean gta_state directory..."
if [[ -z "${GTA_STATE_DIRECTORY}" ]]; then
  MY_GTA_STATE_DIRECTORY="./gta_state"
else
  MY_GTA_STATE_DIRECTORY="${GTA_STATE_DIRECTORY}"
fi

mkdir -p $MY_GTA_STATE_DIRECTORY
rm $MY_GTA_STATE_DIRECTORY/*
echo ""

num_ok=0
num_fails=0
failed_functions=()

assert_success () {
  if [ $? -ne 0 ]
  then 
  ((num_fails=num_fails+1))
  failed_functions+=("$1")
  else 
  ((num_ok=num_ok+1))
  fi
}
assert_error () {
  if [ $? -ne 0 ]
  then
  ((num_ok=num_ok+1))
  else
  ((num_fails=num_fails+1))
  failed_functions+=("$1")
  fi
}

####
# create dummy ca for the tests if dummy ca not exits yet
if ! test -r $TEST_DATA_DIR/ecc_CA.key || ! test -r $TEST_DATA_DIR/ecc_CA.crt
then 
echo "create dummy CA key and dummy CA certificate" 
echo "openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout $TEST_DATA_DIR/ecc_CA.key -out $TEST_DATA_DIR/ecc_CA.crt -nodes -subj "/CN=Dummy CA /O=Dummy Org/C=DE" -days 365"
openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout $TEST_DATA_DIR/ecc_CA.key -out $TEST_DATA_DIR/ecc_CA.crt -nodes -subj "/CN=Dummy CA /O=Dummy Org/C=DE" -days 365
assert_success "openssl_req_-x509"
echo ""
fi

####
# prepare the tests by calling basic gta api calls to create a suitable personality for the opc ecc profile
echo "gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED"
gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED
assert_success "identifier_assign"
echo ""

echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID --app_name=gta-cli --prof=org.opcfoundation.ECC-nistP256"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID --app_name=gta-cli --prof=org.opcfoundation.ECC-nistP256
assert_success "personality_create"
echo ""

####
# tests for personality_enroll with different arguments
# 1. set subject and subjectAltName in csr by using argument --ctx_attr_bin
echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr_bin org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" --ctx_attr_bin org.opcfoundation.csr.subjectAltName="$TEST_DATA_DIR/subjectAltName.der" > $TEST_DATA_DIR/ldevid.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr_bin org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" --ctx_attr_bin org.opcfoundation.csr.subjectAltName="$TEST_DATA_DIR/subjectAltName.der" > $TEST_DATA_DIR/ldevid.csr
assert_success "personality_enroll"cd ..
echo ""

# get LDevID certificate from dummy ca by using csr created with personality_enroll
echo "issue LDevID certificate"
echo "openssl x509 -req -in $TEST_DATA_DIR/ldevid.csr -inform DER -out $TEST_DATA_DIR/ldevid_ee.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
openssl x509 -req -in $TEST_DATA_DIR/ldevid.csr -inform DER -out $TEST_DATA_DIR/ldevid_ee.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall
assert_success "openssl_x509_-req"
echo "openssl x509 -in $TEST_DATA_DIR/ldevid_ee.crt -text"
openssl x509 -in $TEST_DATA_DIR/ldevid_ee.crt -text
assert_success "openssl_x509_-in"
echo ""
# todo: check if subject and subjectAltName in certificate is like expected

# 2. set only subject in csr by using argument --ctx_attr_bin
# subjectAltName should be taken internally from the identifier of the personality
echo "test personality_enroll with setting subjectAltName internally"
echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr_bin org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" > $TEST_DATA_DIR/test1.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr_bin org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" > $TEST_DATA_DIR/test1.csr
assert_success "personality_enroll"
echo ""

# get test1 certificate from dummy ca by using csr created with personality_enroll
echo "issue test1 certificate with subjectAltName taken from personality"
echo "openssl x509 -req -in $TEST_DATA_DIR/test1.csr -inform DER -out $TEST_DATA_DIR/test1.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
openssl x509 -req -in $TEST_DATA_DIR/test1.csr -inform DER -out $TEST_DATA_DIR/test1.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall
assert_success "openssl x509 -req"
openssl x509 -in $TEST_DATA_DIR/test1.crt -text
assert_success "openssl_x509_-in"
echo ""
# todo: check if subject and subjectAltName in certificate is like expected

# 3. don't use argument --ctx_attr_bin
# subject should remain empty and subjectAltName should be taken internally from the identifier of the personality
echo "test personality_enroll without subject and with setting subjectAltName internally"
echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 > $TEST_DATA_DIR/test2.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 > $TEST_DATA_DIR/test2.csr
assert_success "personality_enroll"
echo ""

# get test2 certificate from dummy ca by using csr created with personality_enroll
echo "issue test2 certificate without subject and subjectAltName taken from personality"
echo "openssl x509 -req -in $TEST_DATA_DIR/test2.csr -inform DER -out $TEST_DATA_DIR/test2.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
openssl x509 -req -in $TEST_DATA_DIR/test2.csr -inform DER -out $TEST_DATA_DIR/test2.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall
assert_success "openssl_x509_-req"
openssl x509 -in $TEST_DATA_DIR/test2.crt -text
assert_success "openssl_x509_-in"
echo ""
# todo: check if subject and subjectAltName in certificate is like expected

####
# finish enrollment by adding created LDevID certificate to personality
echo "gta-cli personality_add_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID EE" --attr_val=$TEST_DATA_DIR/ldevid_ee.crt"
gta-cli personality_add_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID EE" --attr_val=$TEST_DATA_DIR/ldevid_ee.crt
assert_success "personality_add_attribute"
echo ""

echo "enroll message flow finished"
echo ""
echo ""

####
# test get enrolled data from gta api
echo "test get enrolled data from gta api"

echo "gta-cli identifier_enumerate"
gta-cli identifier_enumerate
assert_success "identifier_enumerate"
echo ""

echo "gta-cli personality_enumerate --id_val=DE-AD-BE-EF-FE-ED"
gta-cli personality_enumerate --id_val=DE-AD-BE-EF-FE-ED
assert_success "personality_enumerate"
echo ""

echo "gta-cli personality_enumerate_application --app_name=gta-cli"
gta-cli personality_enumerate_application --app_name=gta-cli
assert_success "personality_enumerate_application"
echo ""

echo "gta-cli personality_attributes_enumerate --pers=LDevID"
gta-cli personality_attributes_enumerate --pers=LDevID
assert_success "personality_attributes_enumerate"
echo ""

echo "gta-cli personality_get_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE" > $TEST_DATA_DIR/ldevid_ee.crt"
gta-cli personality_get_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE" > $TEST_DATA_DIR/ldevid_ee.crt
assert_success "personality_get_attribute"
echo ""

####
# test using LDevID personality for signing and verifying signed data with public key of enrolled LDevID certificate
echo "test sign and verify data"
echo "gta-cli authenticate_data_detached --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --data=$TEST_DATA_DIR/plain.txt > $TEST_DATA_DIR/signature.bin"
gta-cli authenticate_data_detached --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --data=$TEST_DATA_DIR/plain.txt > $TEST_DATA_DIR/signature.bin
assert_success "authenticate_data_detached"
echo ""

echo "get public key"
openssl x509 -pubkey -noout -in $TEST_DATA_DIR/ldevid_ee.crt  > $TEST_DATA_DIR/ldevid_ee_pub_key.pem
echo "convert signature from RAW to DER format"
python3 convert_raw_to_der.py ./test_data/signature.bin > $TEST_DATA_DIR/sig.der
echo "verify signature"
openssl dgst -sha256 -verify $TEST_DATA_DIR/ldevid_ee_pub_key.pem -keyform PEM -signature $TEST_DATA_DIR/sig.der $TEST_DATA_DIR/plain.txt
assert_success "openssl_dgst_-sha256_-verify"
echo ""

####
# test remove personality
echo "gta-cli personality_remove_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name=LDevID EE"
gta-cli personality_remove_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE"
assert_success "personality_remove_attribute"
echo ""

# validate successful removal of personality
echo "gta-cli personality_get_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE" > $TEST_DATA_DIR/ldevid_ee.crt"
gta-cli personality_get_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE" > $TEST_DATA_DIR/ldevid_ee.crt
assert_error "personality_get_attribute"
echo ""

num_tests=$(($num_ok+$num_fails))

echo ""
echo "SUMMARY:"
echo "   Number of tests  " $num_tests
echo "   Number of ok:    " $num_ok
echo "   Number of fails: " $num_fails

if [ $num_fails -gt 0 ]
then
   echo ""
   echo "FAILED FUNCTIONS:"
   for str in ${failed_functions[@]}; do  
     echo "  " $str
   done
   exit 1
else
   exit 0
fi