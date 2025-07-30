#/* SPDX-License-Identifier: MPL-2.0 */
#/**********************************************************************
# * Copyright (c) 2025, Siemens AG
# **********************************************************************/

TEST_DATA_DIR=./test_data

echo "test enroll message flow"

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

check_for_error () {
  if [ $? -ne 0 ]
  then 
  ((num_fails=num_fails+1))
  failed_functions+=("$1")
  else 
  ((num_ok=num_ok+1))
  fi
}

CMD="gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED"
echo $CMD
$CMD
check_for_error "identifier_assign"
echo ""

CMD="gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID --app_name=gta-cli --prof=org.opcfoundation.ECC-nistP256"
echo $CMD
$CMD
check_for_error "personality_create"
echo ""

echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" --ctx_attr org.opcfoundation.csr.subjectAltName="$TEST_DATA_DIR/subjectAltName.der" > $TEST_DATA_DIR/ldevid.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" --ctx_attr org.opcfoundation.csr.subjectAltName="$TEST_DATA_DIR/subjectAltName.der" > $TEST_DATA_DIR/ldevid.csr
check_for_error "personality_enroll"cd ..
echo ""

if ! test -r $TEST_DATA_DIR/ecc_CA.key || ! test -r $TEST_DATA_DIR/ecc_CA.crt
then 
echo "create dummy CA key and dummy CA certificate" 
echo "openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout $TEST_DATA_DIR/ecc_CA.key -out $TEST_DATA_DIR/ecc_CA.crt -nodes -subj "/CN=Dummy CA /O=Dummy Org/C=DE" -days 365"
openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout $TEST_DATA_DIR/ecc_CA.key -out $TEST_DATA_DIR/ecc_CA.crt -nodes -subj "/CN=Dummy CA /O=Dummy Org/C=DE" -days 365
check_for_error "openssl_req_-x509"
echo ""
fi

echo "issue LDevID certificate"
CMD="openssl x509 -req -in $TEST_DATA_DIR/ldevid.csr -inform DER -out $TEST_DATA_DIR/ldevid_ee.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
echo $CMD
$CMD
check_for_error "openssl_x509_-req"
CMD="openssl x509 -in $TEST_DATA_DIR/ldevid_ee.crt -text"
echo $CMD
$CMD
check_for_error "openssl_x509_-in"
echo ""

echo "gta-cli personality_add_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID EE" --attr_val=$TEST_DATA_DIR/ldevid_ee.crt"
gta-cli personality_add_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID EE" --attr_val=$TEST_DATA_DIR/ldevid_ee.crt
check_for_error "personality_add_attribute"
echo ""

echo "enroll message flow finished"
echo ""
echo ""

echo "test get enrolled data from gta api"

CMD="gta-cli identifier_enumerate"
echo $CMD
$CMD
check_for_error "identifier_enumerate"
echo ""

CMD="gta-cli personality_enumerate --id_val=DE-AD-BE-EF-FE-ED"
echo $CMD
$CMD
check_for_error "personality_enumerate"
echo ""

CMD="gta-cli personality_enumerate_application --app_name=gta-cli"
echo $CMD
$CMD
check_for_error "personality_enumerate_application"
echo ""

CMD="gta-cli personality_attributes_enumerate --pers=LDevID"
echo $CMD
$CMD
check_for_error "personality_attributes_enumerate"
echo ""

echo "gta-cli personality_get_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE" > $TEST_DATA_DIR/ldevid_ee.crt"
gta-cli personality_get_attribute --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --attr_name="LDevID EE" > $TEST_DATA_DIR/ldevid_ee.crt
check_for_error "personality_get_attribute"
echo ""

echo "test sign and verify data"
echo "gta-cli authenticate_data_detached --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --data=$TEST_DATA_DIR/plain.txt > $TEST_DATA_DIR/signature.bin"
gta-cli authenticate_data_detached --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --data=$TEST_DATA_DIR/plain.txt > $TEST_DATA_DIR/signature.bin
check_for_error "authenticate_data_detached"
echo ""

echo "get public key"
openssl x509 -pubkey -noout -in $TEST_DATA_DIR/ldevid_ee.crt  > $TEST_DATA_DIR/ldevid_ee_pub_key.pem
echo "convert signature from RAW to DER format"
python3 convert_raw_to_der.py ./test_data/signature.bin > $TEST_DATA_DIR/sig.der
echo "verify signature"
openssl dgst -sha256 -verify $TEST_DATA_DIR/ldevid_ee_pub_key.pem -keyform PEM -signature $TEST_DATA_DIR/sig.der $TEST_DATA_DIR/plain.txt
check_for_error "openssl_dgst_-sha256_-verify"
echo ""

echo "test personality_enroll with setting subjectAltName internally"
echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" > $TEST_DATA_DIR/new.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr org.opcfoundation.csr.subject="$TEST_DATA_DIR/subject.der" > $TEST_DATA_DIR/new.csr
check_for_error "personality_enroll"
echo ""

echo "issue new certificate with subjectAltName taken from personality"
echo "openssl x509 -req -in $TEST_DATA_DIR/new.csr -inform DER -out $TEST_DATA_DIR/new.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
openssl x509 -req -in $TEST_DATA_DIR/new.csr -inform DER -out $TEST_DATA_DIR/new.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall
check_for_error "openssl x509 -req"
openssl x509 -in $TEST_DATA_DIR/new.crt -text
check_for_error "openssl_x509_-in"
echo ""

echo "test personality_enroll without subject and setting subjectAltName internally"
echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 > $TEST_DATA_DIR/new2.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 > $TEST_DATA_DIR/new2.csr
check_for_error "personality_enroll"
echo ""

echo "issue new certificate without subject and subjectAltName taken from personality"
echo "openssl x509 -req -in $TEST_DATA_DIR/new2.csr -inform DER -out $TEST_DATA_DIR/new2.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
openssl x509 -req -in $TEST_DATA_DIR/new2.csr -inform DER -out $TEST_DATA_DIR/new2.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall
check_for_error "openssl_x509_-req"
openssl x509 -in $TEST_DATA_DIR/new2.crt -text
check_for_error "openssl_x509_-in"
echo ""

echo "test personality_enroll with --ctx_attr_file option"
echo "gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr_file="$TEST_DATA_DIR/ctx_attr_opc.txt" > $TEST_DATA_DIR/new3.csr"
gta-cli personality_enroll --pers=LDevID --prof=org.opcfoundation.ECC-nistP256 --ctx_attr_file="$TEST_DATA_DIR/ctx_attr_opc.txt" > $TEST_DATA_DIR/new3.csr
check_for_error "personality_enroll"
echo ""

echo "issue new certificate with subject and subjectAltName taken from ctx_attr_file"
echo "openssl x509 -req -in $TEST_DATA_DIR/new3.csr -inform DER -out $TEST_DATA_DIR/new3.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall"
openssl x509 -req -in $TEST_DATA_DIR/new3.csr -inform DER -out $TEST_DATA_DIR/new3.crt -CA $TEST_DATA_DIR/ecc_CA.crt -CAkey $TEST_DATA_DIR/ecc_CA.key -CAcreateserial -days 9125 -extensions v3_req -copy_extensions copyall
check_for_error "openssl_x509_-req"
openssl x509 -in $TEST_DATA_DIR/new3.crt -text
check_for_error "openssl_x509_-in"
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