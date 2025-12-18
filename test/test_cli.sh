#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

: "${GTA_CLI_BINARY:="gta-cli"}"
: "${TEST_DIRECTORY:="./test_tmp"}"

echo "clean gta_state directory..."
if [[ -z "${GTA_STATE_DIRECTORY}" ]]; then
  GTA_STATE_DIRECTORY="${TEST_DIRECTORY}/gta_state"
fi

export GTA_STATE_DIRECTORY

mkdir -p "$GTA_STATE_DIRECTORY"
rm -f "$GTA_STATE_DIRECTORY/"*
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


echo "gta-cli devicestate_recede"
"$GTA_CLI_BINARY" devicestate_recede
assert_success "devicestate_recede"

echo "gta-cli access_policy_simple --descr_type=INVALID"
"$("$GTA_CLI_BINARY" access_policy_simple --descr_type=INVALID)"
assert_error "access_policy_simple"
echo "gta-cli access_policy_simple"
h_pol_default="$("$GTA_CLI_BINARY" access_policy_simple)"
assert_success "access_policy_simple"
echo "gta-cli access_policy_simple --descr_type=INITIAL"
h_pol_initial="$("$GTA_CLI_BINARY" access_policy_simple --descr_type=INITIAL)"
assert_success "access_policy_simple"
echo "gta-cli access_policy_simple --descr_type=BASIC"
h_pol_basic="$("$GTA_CLI_BINARY" access_policy_simple --descr_type=BASIC)"
assert_success "access_policy_simple"
echo "gta-cli access_policy_simple --descr_type=PHYSICAL_PRESENCE"
h_pol_physical="$("$GTA_CLI_BINARY" access_policy_simple --descr_type=PHYSICAL_PRESENCE)"
assert_success "access_policy_simple"

echo "gta-cli devicestate_transition --acc_pol_recede=$h_pol_physical -owner_lock_count=5"
"$GTA_CLI_BINARY" devicestate_transition --acc_pol_recede="$h_pol_physical" --owner_lock_count=5
assert_success "devicestate_transition"

echo "gta-cli devicestate_recede"
"$GTA_CLI_BINARY" devicestate_recede
assert_success "devicestate_recede"

echo "gta-cli devicestate_transition --acc_pol_recede=$h_pol_physical --owner_lock_count=5"
"$GTA_CLI_BINARY" devicestate_transition --acc_pol_recede="$h_pol_physical" --owner_lock_count=5
assert_success "devicestate_transition"
echo ""

echo "gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED"
"$GTA_CLI_BINARY" identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED
assert_success "identifier_assign"
echo "gta-cli identifier_assign --id_type=ch.iec.30168.identifier.uuid --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
"$GTA_CLI_BINARY" identifier_assign --id_type=ch.iec.30168.identifier.uuid --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6
assert_success "identifier_assign"
echo ""

echo "gta-cli identifier_enumerate"
"$GTA_CLI_BINARY" identifier_enumerate
assert_success "identifier_enumerate"
echo ""

echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_seal_data --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use=$h_pol_initial --acc_pol_admin=$h_pol_initial"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_seal_data --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use="$h_pol_initial" --acc_pol_admin="$h_pol_initial"
assert_success "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_basic --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use=$h_pol_basic --acc_pol_admin=$h_pol_basic"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_basic --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use="$h_pol_basic" --acc_pol_admin="$h_pol_basic"
assert_success "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_physical --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use=$h_pol_physical --acc_pol_admin=$h_pol_physical"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_physical --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use="$h_pol_physical" --acc_pol_admin="$h_pol_physical"
assert_error "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_physical_2 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use=$h_pol_physical --acc_pol_admin=$h_pol_initial"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_physical_2 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use="$h_pol_physical" --acc_pol_admin="$h_pol_initial"
assert_error "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_dummy_2 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use=$h_pol_initial"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_dummy_2 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_use="$h_pol_initial"
assert_success "personality_create"
echo "gta-cli personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_3 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_admin=$h_pol_default"
"$GTA_CLI_BINARY" personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_3 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection --acc_pol_admin="$h_pol_default"
assert_success "personality_create"
echo "gta-cli personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_4 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection"
"$GTA_CLI_BINARY" personality_create --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers=test_pers_dummy_4 --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection
assert_success "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_ec_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.ec"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_ec_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.ec
assert_success "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_rsa_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.rsa"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_rsa_default --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.rsa
assert_success "personality_create"
echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_rsa_default_delete --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.rsa"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_rsa_default_delete --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.rsa
assert_success "personality_create"
echo ""

echo "< ./test_data/plain.txt gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection > ${TEST_DIRECTORY}/out.enc"
< ./test_data/plain.txt "$GTA_CLI_BINARY" seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection > "${TEST_DIRECTORY}/out.enc"
assert_success "seal_data"
echo "< ${TEST_DIRECTORY}/out.enc gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection"
< "${TEST_DIRECTORY}/out.enc" "$GTA_CLI_BINARY" unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection
assert_success "unseal_data"
echo ""

echo "gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=./test_data/plain.txt > ${TEST_DIRECTORY}/out2.enc"
"$GTA_CLI_BINARY" seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=./test_data/plain.txt > "${TEST_DIRECTORY}/out2.enc"
assert_success "seal_data"
echo "gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data=${TEST_DIRECTORY}/out2.enc"
"$GTA_CLI_BINARY" unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_protection --data="${TEST_DIRECTORY}/out2.enc"
assert_success "seal_data"
echo ""

echo "< ./test_data/plain.txt gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only > ${TEST_DIRECTORY}/out.enc"
< ./test_data/plain.txt "$GTA_CLI_BINARY" seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only > "${TEST_DIRECTORY}/out.enc"
assert_success "seal_data"
echo "< ${TEST_DIRECTORY}/out.enc gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only"
< "${TEST_DIRECTORY}/out.enc" "$GTA_CLI_BINARY" unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only
assert_success "unseal_data"
echo ""

echo "gta-cli seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt > ${TEST_DIRECTORY}/out.enc"
"$GTA_CLI_BINARY" seal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt > "${TEST_DIRECTORY}out.enc"
assert_success "seal_data"
echo "gta-cli unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=${TEST_DIRECTORY}/out.enc"
"$GTA_CLI_BINARY" unseal_data --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data="${TEST_DIRECTORY}/out.enc"
assert_success "unseal_data"
echo ""

echo "gta-cli seal_data --pers=test_pers_basic --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt > ${TEST_DIRECTORY}/out.enc"
"$GTA_CLI_BINARY" seal_data --pers=test_pers_basic --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt > "${TEST_DIRECTORY}out.enc"
assert_error "seal_data"

echo "gta-cli authenticate_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt > ${TEST_DIRECTORY}/out.icv"
"$GTA_CLI_BINARY" authenticate_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt > "${TEST_DIRECTORY}/out.icv"
assert_success "authenticate_data_detached"
echo "gta-cli verify_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt --seal=${TEST_DIRECTORY}/out.icv"
"$GTA_CLI_BINARY" verify_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --data=./test_data/plain.txt --seal="${TEST_DIRECTORY}/out.icv"
assert_success "verify_data_detached"
echo ""

echo "< ./test_data/plain.txt gta-cli authenticate_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only > ${TEST_DIRECTORY}/out.icv"
< ./test_data/plain.txt "$GTA_CLI_BINARY" authenticate_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only > "${TEST_DIRECTORY}/out.icv"
assert_success "authenticate_data_detached"
echo "< ./test_data/plain.txt gta-cli verify_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --seal=${TEST_DIRECTORY}/out.icv"
< ./test_data/plain.txt "$GTA_CLI_BINARY" verify_data_detached --pers=test_pers_seal_data --prof=ch.iec.30168.basic.local_data_integrity_only --seal="${TEST_DIRECTORY}/out.icv"
assert_success "verify_data_detached"
echo ""

echo "gta-cli personality_enumerate --id_val=DE-AD-BE-EF-FE-ED"
"$GTA_CLI_BINARY" personality_enumerate --id_val=DE-AD-BE-EF-FE-ED
assert_success "personality_enumerate"
echo "gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ALL" 
"$GTA_CLI_BINARY" personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ALL
assert_success "personality_enumerate"
echo "gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ACTIVE" 
"$GTA_CLI_BINARY" personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=ACTIVE
assert_success "personality_enumerate"
echo "gta-cli personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=INACTIVE" 
"$GTA_CLI_BINARY" personality_enumerate --id_val=f81d4fae-7dec-11d0-a765-00a0c91e6bf6 --pers_flag=INACTIVE
assert_success "personality_enumerate"
echo ""

echo "gta-cli personality_enumerate_application --app_name=gta-cli"
"$GTA_CLI_BINARY" personality_enumerate_application --app_name=gta-cli
assert_success "personality_enumerate_application"
echo ""

echo "gta-cli personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST --attr_val=./test_data/attr_value_test.txt"
"$GTA_CLI_BINARY" personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST --attr_val=./test_data/attr_value_test.txt
assert_success "personality_add_attribute"
echo "< ./test_data/attr_value_test.txt gta-cli personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST_2"
< ./test_data/attr_value_test.txt "$GTA_CLI_BINARY" personality_add_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name=ATTR_NAME_TEST_2
assert_success "personality_add_attribute"
echo ""

echo "gta-cli personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST"
"$GTA_CLI_BINARY" personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST
assert_success "personality_get_attribute"
echo ""
echo ""
echo "gta-cli personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2"
"$GTA_CLI_BINARY" personality_get_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2
assert_success "personality_get_attribute"
echo ""

echo "gta-cli personality_attributes_enumerate --pers=test_pers_ec_default"
"$GTA_CLI_BINARY" personality_attributes_enumerate --pers=test_pers_ec_default
assert_success "personality_attributes_enumerate"
echo ""

echo "gta-cli personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST"
"$GTA_CLI_BINARY" personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST
assert_success "personality_remove_attribute"
echo ""
echo "gta-cli personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2"
"$GTA_CLI_BINARY" personality_remove_attribute --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --attr_name=ATTR_NAME_TEST_2
assert_success "personality_remove_attribute"
echo ""

echo "gta-cli personality_attributes_enumerate --pers=test_pers_ec_default"
"$GTA_CLI_BINARY" personality_attributes_enumerate --pers=test_pers_ec_default
assert_success "personality_attributes_enumerate"
echo ""

echo "gta-cli authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --data=./test_data/plain.txt  > ${TEST_DIRECTORY}/sig.bin"
"$GTA_CLI_BINARY" authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls --data=./test_data/plain.txt > "${TEST_DIRECTORY}/sig.bin"
assert_success "authenticate_data_detached"
echo "< ./test_data/plain.txt gta-cli authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls  > ${TEST_DIRECTORY}/sig2.bin"
< ./test_data/plain.txt "$GTA_CLI_BINARY" authenticate_data_detached --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls  > "${TEST_DIRECTORY}/sig2.bin"
assert_success "authenticate_data_detached"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls"
"$GTA_CLI_BINARY" personality_enroll --pers=test_pers_ec_default --prof=com.github.generic-trust-anchor-api.basic.tls
assert_success "personality_enroll"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.jwt"
"$GTA_CLI_BINARY" personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.jwt
assert_success "personality_enroll"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll  --ctx_attr com.github.generic-trust-anchor-api.enroll.subject_rdn=CN=Device1"
"$GTA_CLI_BINARY" personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr com.github.generic-trust-anchor-api.enroll.subject_rdn="CN=Device1"
assert_success "personality_enroll"
echo ""

echo "gta-cli personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr_file=./test_data/ctx_attr.txt"
"$GTA_CLI_BINARY" personality_enroll --pers=test_pers_rsa_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr_file=./test_data/ctx_attr.txt
assert_success "personality_enroll"
echo ""

echo "gta-cli personality_remove --pers=test_pers_rsa_default_delete --prof=com.github.generic-trust-anchor-api.basic.tls"
"$GTA_CLI_BINARY" personality_remove --pers=test_pers_rsa_default_delete --prof=com.github.generic-trust-anchor-api.basic.tls
assert_success "personality_remove"
# validate successful removal of personality
"$GTA_CLI_BINARY" personality_enumerate --id_val=DE-AD-BE-EF-FE-ED | grep "test_pers_rsa_default_delete"
assert_error "personality_remove"
echo ""

echo "gta-cli devicestate_transition --acc_pol_recede=$h_pol_physical --owner_lock_count=5"
"$GTA_CLI_BINARY" devicestate_transition --acc_pol_recede="$h_pol_physical" --owner_lock_count=5
assert_success "devicestate_transition"

echo "gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_devicestates --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection"
"$GTA_CLI_BINARY" personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=test_pers_devicestates --app_name=gta-cli --prof=ch.iec.30168.basic.local_data_protection
assert_success "personality_create"

echo "gta-cli personality_enumerate_application --app_name=gta-cli"
"$GTA_CLI_BINARY" personality_enumerate_application --app_name=gta-cli
assert_success "personality_enumerate_application"

echo "gta-cli devicestate_recede"
"$GTA_CLI_BINARY" devicestate_recede
assert_success "devicestate_recede"

echo "gta-cli personality_enumerate_application --app_name=gta-cli"
"$GTA_CLI_BINARY" personality_enumerate_application --app_name=gta-cli
assert_success "personality_enumerate_application"

echo "gta-cli devicestate_recede"
"$GTA_CLI_BINARY" devicestate_recede
assert_success "devicestate_recede"

echo "gta-cli personality_enumerate_application --app_name=gta-cli"
"$GTA_CLI_BINARY" personality_enumerate_application --app_name=gta-cli
assert_success "personality_enumerate_application"
echo ""

num_tests=$((num_ok + num_fails))

echo ""
echo "SUMMARY:"
echo "   Number of tests  " $num_tests
echo "   Number of ok:    " $num_ok
echo "   Number of fails: " $num_fails

if [ $num_fails -gt 0 ]
then
   echo ""
   echo "FAILED FUNCTIONS:"
   for str in "${failed_functions[@]}"; do  
     echo "  " "$str"
   done
   exit 1
else
   exit 0
fi
