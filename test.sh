#!/bin/bash

TESTFILE=$1
KEYFILE=$2


ENC_CLI="./cli -e -i $TESTFILE -o ${TESTFILE}.enc"
DEC_CLI="./cli -d -i ${TESTFILE}.enc -o ${TESTFILE}.plain"

ENC_GUI="./yaxafileutil -q -e -i $TESTFILE -o ${TESTFILE}.enc"
DEC_GUI="./yaxafileutil -q -d -i ${TESTFILE}.enc -o ${TESTFILE}.plain"

ENC_CLI_OTP="./cli -e -i $TESTFILE -o ${TESTFILE}.enc -O /dev/urandom"
DEC_CLI_OTP="./cli -d -i ${TESTFILE}.enc -o ${TESTFILE}.plain -O ${TESTFILE}.enc.pad"

ENC_GUI_OTP="./yaxafileutil -q -e -i $TESTFILE -o ${TESTFILE}.enc -O /dev/urandom"
DEC_GUI_OTP="./yaxafileutil -q -d -i ${TESTFILE}.enc -o ${TESTFILE}.plain -O ${TESTFILE}.enc.pad"

CMP_RES="cmp ${TESTFILE} ${TESTFILE}.plain"

echo_do() {
    echo -e "\t$@"
    bash -c "$@"
}

do_test() {
    echo_do "$ENC_CLI $@"
    echo_do "$DEC_CLI $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_GUI $@"
    echo_do "$DEC_GUI $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_GUI $@"
    echo_do "$DEC_CLI $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_CLI $@"
    echo_do "$DEC_GUI $@"
    bash -c "$CMP_RES"
    echo ""
}

do_test_otp() {
    echo_do "$ENC_CLI_OTP $@"
    echo_do "$DEC_CLI_OTP $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_GUI_OTP $@"
    echo_do "$DEC_GUI_OTP $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_GUI_OTP $@"
    echo_do "$DEC_CLI_OTP $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_CLI_OTP $@"
    echo_do "$DEC_GUI_OTP $@"
    bash -c "$CMP_RES"
    echo ""
}

echo "Testing with password and default paramaters"
do_test "-p password"

echo "Testing with password and non-default scrypt work factors"
do_test "-p password -w N=1024"

echo "Testing with password and non-default scrypt work factors, and non-default key size"
do_test "-p password -w N=1024 -s key_size=64b"

echo "Testing with password and non-default scrypt work factors, non-default key size and non-default buffers"
do_test "-p password -w N=1024 -s key_size=64b,mac_buffer=64m,message_buffer=64m"

echo "Testing with keyfile with default parameters"
do_test "-k $KEYFILE"

echo "Testing with keyfile and password with default parameters"
do_test "-k $KEYFILE -p password"

echo "Testing with keyfile and password with non-default keysize"
do_test "-k $KEYFILE -p password -s key_size=64b"

echo "Testing with keyfile and password with non-default scrypt work factors and non-default buffers"
do_test "-k $KEYFILE -p password -w N=1024 -s mac_buffer=64m,message_buffer=64m"

echo "Testing with one-time-pad and defaults"
do_test_otp ""

echo "Testing with one-time-pad and password with default parameters"
do_test_otp "-p password"

echo "Testing with one-time-pad and password with non-default scrypt parameters"
do_test_otp "-p password -w N=1024"

echo "Testing with one-time-pad and password with non-default scrypt parameters and keysize"
do_test_otp "-p password -w N=1024 -s key_size=64b"

echo "Testing with one-time-pad and password with non-default scrypt parameters, keysize and non-default buffers"
do_test_otp "-p password -w N=1024 -s key_size=64b,mac_buffer=64m,message_buffer=64m"
