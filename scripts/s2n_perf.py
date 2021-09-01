#!/bin/bash -

set -e

if ! git update-index --refresh; then
    echo "Uncommited changes detected. Please stash or commit before running this script."
    exit 1
fi

if command -v perf >/dev/null 2>&1 ; then
    echo "perf installed: $(perf -v)"
else
    echo "perf not installed"
    exit 1
fi

ROOT_DIR=$(pwd)
CURRENT=$(git rev-parse --abbrev-ref HEAD)
FLAMEGRAPH_DIR=$ROOT_DIR/test-deps/flamegraph
STACK_COLLAPSE_SCRIPT=$FLAMEGRAPH_DIR/stackcollapse-perf.pl
FLAMEGRAPH_SCRIPT=$FLAMEGRAPH_DIR/flamegraph.pl

if [ ! -d $FLAMEGRAPH_DIR ]; then
    mkdir $FLAMEGRAPH_DIR
    BUILD_DIR=$(mktemp -d)
    cd $BUILD_DIR
    git init
    git clone https://github.com/brendangregg/FlameGraph.git
    cp $BUILD_DIR/FlameGraph/stackcollapse-perf.pl $FLAMEGRAPH_DIR
    cp $BUILD_DIR/FlameGraph/flamegraph.pl $FLAMEGRAPH_DIR
    cd $ROOT_DIR
fi

COMPARE_TO=main
OUTPUT_FOLDER=$ROOT_DIR
FILE_NAME=result
METHOD_NAME=main
while getopts ":c:o:f:m:" opt; do
  case ${opt} in
    c )
      COMPARE_TO=$OPTARG
      ;;
    o )
      OUTPUT_FOLDER=$OPTARG
      ;;
    f )
      FILE_NAME=$OPTARG
      ;;
    m )
      METHOD_NAME=$OPTARG
      ;;
    \? )
      echo "Invalid option: $OPTARG" 1>&2
      exit 1
      ;;
    : )
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))
COMMAND=$@

do_perf() {
    BRANCH=$1
    OUTPUT_SVG=$OUTPUT_FOLDER/${FILE_NAME}_${BRANCH}.svg
    TMP_DIR=$(mktemp -d)
    
    git checkout --quiet $BRANCH
    
    echo ""
    echo "==== running $COMMAND ===="
    sudo perf record \
      --quiet \
      --output $TMP_DIR/out.data \
      --call-graph dwarf \
      --event cycles \
      $COMMAND
    sudo perf script --input $TMP_DIR/out.data > $TMP_DIR/out.perf
    sudo chmod +r $TMP_DIR/out.perf

    $STACK_COLLAPSE_SCRIPT $TMP_DIR/out.perf > $TMP_DIR/out.folded
    $FLAMEGRAPH_SCRIPT $TMP_DIR/out.folded > $OUTPUT_SVG
    CPU_SHARE=$(grep "<title>$METHOD_NAME (" $OUTPUT_SVG | sed -r "s/^.*? ([0-9.]+%).*?$/\1/")
    
    echo ""
    echo "==== $BRANCH: $METHOD_NAME ===="
    echo "Wrote flamegraph to $OUTPUT_SVG"
    echo "CPU share: ${CPU_SHARE:=0%}"
}

echo "Comparing '$METHOD_NAME' in '$COMMAND': $COMPARE_TO vs $CURRENT"

do_perf $COMPARE_TO
do_perf $CURRENT

