echo nix/shell.sh: Entering a devShell
export SRC_ROOT=$(pwd)
export PATH=$SRC_ROOT/build/bin:$PATH

# The GnuTlS config may restrict TLS versions in some environments,
# so do not use any existing config file.
export GNUTLS_SYSTEM_PRIORITY_FILE=

# Function to create aliases for different libcrypto implementations
function libcrypto_alias {
    local libcrypto_name=$1
    local libcrypto_binary_path=$2
    # Check both bin and lib directories for the binary
    local binary_dir=$(dirname $libcrypto_binary_path)
    local install_dir=$(dirname $binary_dir)
    local lib_binary_path="$install_dir/lib/$(basename $libcrypto_binary_path)"

    if [[ -f $libcrypto_binary_path ]]; then
      alias $libcrypto_name=$libcrypto_binary_path
      echo "Libcrypto binary $libcrypto_binary_path available as $libcrypto_name"
    elif [[ -f $lib_binary_path ]]; then
      alias $libcrypto_name=$lib_binary_path
      echo "Libcrypto binary $lib_binary_path available as $libcrypto_name"
    else
      echo "Could not find libcrypto binary for $libcrypto_name"
    fi
}
libcrypto_alias openssl102 "${OPENSSL_1_0_2_INSTALL_DIR}/bin/openssl"
libcrypto_alias openssl111 "${OPENSSL_1_1_1_INSTALL_DIR}/bin/openssl"
libcrypto_alias openssl30 "${OPENSSL_3_0_INSTALL_DIR}/bin/openssl"
libcrypto_alias awslc "${AWSLC_INSTALL_DIR}/bin/bssl"
libcrypto_alias awslcfips2022 "${AWSLC_FIPS_2022_INSTALL_DIR}/bin/bssl"
libcrypto_alias awslcfips2024 "${AWSLC_FIPS_2024_INSTALL_DIR}/bin/bssl"
libcrypto_alias libressl "${LIBRESSL_INSTALL_DIR}/bin/openssl"
# No need to alias gnutls because it is included in common_packages (see flake.nix).

function clean {(set -e
    echo "Cleaning up build, s2n_head and the apache2 configs"
    rm -rf ./build ./s2n_head
    if [ -d "/usr/local/apache2" ]; then
        rm -rf /usr/local/apache2
    fi
)}

function configure {(set -e
    echo "Configuring with cmake"
    cmake -S . -B./build \
          -DBUILD_TESTING=ON \
          -DS2N_INTEG_TESTS=ON \
          -DS2N_INSTALL_S2NC_S2ND=ON \
          -DS2N_INTEG_NIX=ON \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          "$S2N_CMAKE_OPTIONS" \
          -DCMAKE_BUILD_TYPE=RelWithDebInfo
)}

function build {(set -e
    echo "Running Build"
    javac tests/integrationv2/bin/SSLSocketClient.java
    cmake --build ./build -j $(nproc)
    # Build s2n from HEAD
    if [[ -z "${S2N_KTLS_TESTING_EXPECTED}" && -z "${S2N_NO_HEADBUILD}" ]]; then
        $SRC_ROOT/codebuild/bin/install_s2n_head.sh $(mktemp -d)
    fi
)}

function unit {(set -e
    if [[ -z "$1" ]]; then
        cmake --build build -j $(nproc)
        ctest --test-dir build -L unit -j $(nproc) --verbose
    else
        tests=$(ctest --test-dir build -N -L unit | grep -E "Test +#" | grep -Eo "[^ ]+_test$" | grep "$1")
        # Split the tests string into words
        for test in $tests
        do
            cmake --build build -j $(nproc) --target $test
        done
        ctest --test-dir build -L unit -R "$1" -j $(nproc) --verbose
    fi
)}

# Function to launch pytest with uv.
function uvinteg {(
    set -eu
    TESTS="${1:-all}"
    apache2_start
    # TODO: Dynamic Record Sizes needs a rewrite; skip for now.
    PYTEST_ARGS="--provider-version $S2N_LIBCRYPTO -x -n auto --reruns=2 --durations=10 -rpfs --cache-clear --ignore-glob=*test_dynamic_record_sizes*"
    cd ./tests/integrationv2
    echo -n "Comparing the current list of integ tests against what is checked-in..."
    PYTHONPATH="" uv run pytest --collect-only $PYTEST_ARGS | grep Module > /tmp/uvinteg_tests.txt
    diff -q /tmp/uvinteg_tests.txt uvinteg_tests.txt
    echo "tests to run match uvinteg_tests.txt."
    if [[ "$TESTS" == "all" ]]; then
        echo "Running all integ tests with uv"
        PYTHONPATH="" uv run pytest $PYTEST_ARGS --junitxml=../../build/junit/uv_integ.xml
    else
        for test in "$@"; do
            PYTHONPATH="" uv run pytest $PYTEST_ARGS --junitxml=../../build/junit/$test.xml -k $test
        done
    fi
)}

# Wrap a command with stress to simulate a high-load environment.
# Not intended for CI, but local troubleshooting.
function highstress {(
    set -e
    local STRESSARGS="--cpu $(nproc) --io $(nproc) --quiet"
    echo "Running: stress $STRESSARGS"
    stress $STRESSARGS &
    trap 'pkill stress' ERR EXIT
    "$@"
)}

function check-clang-format {(set -e
    echo "Dry run of clang-format"
    (cd $SRC_ROOT;
    include_regex=".*\.(c|h)$";
    src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    echo $src_files | xargs -n 1 -P $(nproc) clang-format --dry-run -style=file)
)}

function do-clang-format {(set -e
    echo "In place clang-format"
    (cd $SRC_ROOT;
    include_regex=".*\.(c|h)$";
    src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    src_files+=" ";
    src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`;
    echo $src_files | xargs -n 1 -P $(nproc) clang-format -style=file -i)
)}

function test_toolchain_counts {(set -e
    # This is a starting point for a unit test of the devShell.
    # The chosen S2N_LIBCRYPTO should be 2, and the others should be zero.
    echo "Checking the CMAKE_INCLUDE_PATH for libcrypto counts"
    echo $CMAKE_INCLUDE_PATH|gawk 'BEGIN{RS=":"; o10=0; o11=0; o3=0;awslc=0;libre=0}
      /openssl-3.0/{o3++}
      /openssl-1.1/{o11++}
      /openssl-1.0/{o10++}
      /aws-lc/{awslc++}
      /libressl/{libre++}
      END{print "\nOpenssl3:\t",o3,"\nOpenssl1.1:\t",o11,"\nOpenssl1.0.2:\t",o10,"\nAws-lc:\t\t",awslc,"\nLibreSSL:\t", libre}'
    echo "Checking tooling counts (these should all be 1)"
    echo -e "\nOpenssl integ:\t $(openssl version|grep -c '1.1.1')"
    echo -e "Corretto 17:\t $(java -version 2>&1|grep -ce 'Runtime.*Corretto-17')"
    echo -e "gnutls-cli:\t $(gnutls-cli --version |grep -c 'gnutls-cli 3.7')"
    echo -e "gnutls-serv:\t $(gnutls-serv --version |grep -c 'gnutls-serv 3.7')"
    echo -e "Nix Python:\t $(which python|grep -c '/nix/store')"
    echo -e "Nix pytest:\t $(which pytest|grep -c '/nix/store')"
    echo -e "Nix sslyze:\t $(which sslyze|grep -c '/nix/store')"
    echo -e "python nassl:\t $(pip freeze|grep -c 'nassl')"
    echo -e "valgrind:\t $(valgrind --version|grep -c 'valgrind-3.19.0')"
)}

function test_nonstandard_compilation {(set -e
    # Any script that needs to compile s2n in a non-standard way can run here
    ./codebuild/bin/test_dynamic_load.sh $(mktemp -d)
)}

function apache2_config(){
    export APACHE_NIX_STORE=$(dirname $(dirname $(which httpd)))
    export APACHE2_INSTALL_DIR=/usr/local/apache2
    export APACHE_SERVER_ROOT="$APACHE2_INSTALL_DIR"
    export APACHE_RUN_USER=nobody
    # Unprivileged groupname differs
    export APACHE_RUN_GROUP=$(awk 'BEGIN{FS=":"} /65534/{print $1}' /etc/group)
    export APACHE_PID_FILE="${APACHE2_INSTALL_DIR}/run/apache2.pid"
    export APACHE_RUN_DIR="${APACHE2_INSTALL_DIR}/run"
    export APACHE_LOCK_DIR="${APACHE2_INSTALL_DIR}/lock"
    export APACHE_LOG_DIR="${APACHE2_INSTALL_DIR}/log"
    export APACHE_CERT_DIR="$SRC_ROOT/tests/pems"
}

function apache2_start(){
    if [[ "$(pgrep -c httpd)" -eq "0" ]]; then
        apache2_config
        if [[ ! -f "$APACHE2_INSTALL_DIR/conf/apache2.conf" ]]; then
            mkdir -p $APACHE2_INSTALL_DIR/{run,log,lock}
            # NixOs specific base apache config
            cp -R ./tests/integrationv2/apache2/nix/* $APACHE2_INSTALL_DIR
            # Integrationv2::renegotiate site
            cp -R ./codebuild/bin/apache2/{www,sites-enabled} $APACHE2_INSTALL_DIR
        fi
        httpd -k start -f "${APACHE2_INSTALL_DIR}/conf/apache2.conf"
        trap 'pkill httpd' ERR EXIT
    else
      echo "Apache is already running. If \"$APACHE2_INSTALL_DIR\" is stale, it might be in an unknown state."
    fi
}
