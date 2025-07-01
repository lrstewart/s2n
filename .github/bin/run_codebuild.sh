set -e

usage() {
    echo "run_codebuild.sh <repo> <source> <region> <project> [batch]"
    echo ""
    echo "Arguments:"
    echo "  repo        Name of the Github repository. For example: aws/s2n-tls"
    echo "  source      Source version. For example: pr/1234, 1234abcd, test_branch"
    echo "  region      AWS region of Codebuild project. For example: us-west-2"
    echo "  project     Name of the Codebuild project. For example: AddressSanitizer"
    echo "  batch       Either 'batch' or 'no-batch'. Defaults to 'batch'"
}

if [ "$#" -lt "4" ]; then
    usage
    exit 1
fi
REPO=$1
SOURCE_VERSION=$2
REGION=$3
NAME=$4
BATCH=${5:-"batch"}

START_COMMAND="start-build-batch"
GET_COMMAND="batch-get-build-batches"
if [ "$BATCH" = "no-batch" ]; then
    START_COMMAND="start-build"
    GET_COMMAND="batch-get-builds"
fi

BUILD_ID=$(aws --region $REGION codebuild $START_COMMAND --project-name $NAME --source-location-override https://github.com/$REPO --source-version $SOURCE_VERSION | jq -r .build.id)
echo "Launched build: $BUILD_ID"

STATUS="IN_PROGRESS"
until [ "$STATUS" != "IN_PROGRESS" ]; do
    sleep 600
    STATUS=$(aws --region $REGION codebuild $GET_COMMAND --id $BUILD_ID | jq -r '.builds[0].buildStatus')
    echo "Status: $STATUS"
done

if [ "$STATUS" = "SUCCEEDED" ]; then
    exit 0
else
    exit 1
fi