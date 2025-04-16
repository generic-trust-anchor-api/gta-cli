#/* SPDX-License-Identifier: MPL-2.0 */
#/**********************************************************************
# * Copyright (c) 2025, Siemens AG
# **********************************************************************/

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

echo "gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED"
gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED
check_for_error "identifier_assign"
echo "gta-cli identifier_assign --id_type=ch.iec.30168.identifier.uuid --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
gta-cli identifier_assign --id_type=ch.iec.30168.identifier.uuid --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6
check_for_error "identifier_assign"
echo ""

echo "gta-cli identifier_enumerate"
gta-cli identifier_enumerate
check_for_error "identifier_enumerate"
echo ""

echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_seal_data --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_seal_data --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection
check_for_error "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_dummy_2 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_dummy_2 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection
check_for_error "personality_create"
echo "gta-cli personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_3 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection"
gta-cli personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_3 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection
check_for_error "personality_create"
echo "gta-cli personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_4 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection"
gta-cli personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_4 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection
check_for_error "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_ec_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.ec"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_ec_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.ec
check_for_error "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_rsa_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.rsa"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_rsa_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.rsa
check_for_error "personality_create"
echo ""

echo "cat ./test_data/plain.txt | gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection > ./test_data/out.enc"
cat ./test_data/plain.txt | gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection > ./test_data/out.enc
check_for_error "seal_data"
echo "cat ./test_data/out.enc | gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection"
cat ./test_data/out.enc | gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection
check_for_error "unseal_data"
echo ""

echo "gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=./test_data/plain.txt > ./test_data/out2.enc"
gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=./test_data/plain.txt > ./test_data/out2.enc
check_for_error "seal_data"
echo "gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=./test_data/out2.enc"
gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=./test_data/out2.enc
check_for_error "seal_data"
echo ""

echo "gta-cli personality_enumerate --id_val=DE-AD-BE-EF-FE-ED"
gta-cli personality_enumerate --id_val=DE-AD-BE-EF-FE-ED
check_for_error "personality_enumerate"
echo "gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ALL" 
gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ALL
check_for_error "personality_enumerate"
echo "gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ACTIVE" 
gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ACTIVE
check_for_error "personality_enumerate"
echo "gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=INACTIVE" 
gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=INACTIVE
check_for_error "personality_enumerate"
echo ""

echo "gta-cli personality_enumerate_application --app_name=gta-cli"
gta-cli personality_enumerate_application --app_name=gta-cli
check_for_error "personality_enumerate_application"
echo ""

echo "gta-cli personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST --attr_val=./test_data/attr_value_test.txt"
gta-cli personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST --attr_val=./test_data/attr_value_test.txt
check_for_error "personality_add_attribute"
echo "cat ./test_data/attr_value_test.txt | gta-cli personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST_2"
cat ./test_data/attr_value_test.txt | gta-cli personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST_2
check_for_error "personality_add_attribute"
echo ""

echo "gta-cli personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST"
gta-cli personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST
check_for_error "personality_get_attribute"
echo ""
echo ""
echo "gta-cli personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2"
gta-cli personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2
check_for_error "personality_get_attribute"
echo ""

echo "gta-cli personality_attributes_enumerate --pers=test_pers_ec_default"
gta-cli personality_attributes_enumerate --pers=test_pers_ec_default
check_for_error "personality_attributes_enumerate"
echo ""

echo "gta-cli personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST"
gta-cli personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST
check_for_error "personality_remove_attribute"
echo ""
echo "gta-cli personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2"
gta-cli personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2
check_for_error "personality_remove_attribute"
echo ""

echo "gta-cli personality_attributes_enumerate --pers=test_pers_ec_default"
gta-cli personality_attributes_enumerate --pers=test_pers_ec_default
check_for_error "personality_attributes_enumerate"
echo ""

echo "gta-cli authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --data=./test_data/plain.txt  > ./test_data/sig.bin"
gta-cli authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --data=./test_data/plain.txt > ./test_data/sig.bin
check_for_error "authenticate_data_detached"
echo "cat ./test_data/plain.txt | gta-cli authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls  > ./test_data/sig2.bin"
cat ./test_data/plain.txt | gta-cli authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls  > ./test_data/sig2.bin
check_for_error "authenticate_data_detached"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls"
gta-cli personality_enroll --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls
check_for_error "personality_enroll"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.jwt"
gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.jwt
check_for_error "personality_enroll"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll  --ctx_attr com.github.generic-trust-anchor-api.enroll.subject_rdn=CN=Device1"
gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr com.github.generic-trust-anchor-api.enroll.subject_rdn="CN=Device1"
check_for_error "personality_enroll"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr_file=./test_data/ctx_attr.txt"
gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr_file=./test_data/ctx_attr.txt
check_for_error "personality_enroll"
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