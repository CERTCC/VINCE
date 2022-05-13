#!/bin/bash
set -e

usage() {
    echo "Usage: $0 [-s ISO8660_timestamp] [-e ISO8660_timestamp] [-l #ofentries] <component>"
    echo "  -s: Start timestamp (ex.: 20210414T14:05:00)"
    echo "  -e: End timestamp"
    echo "  -l: Return X most recent entries"
    echo ""
    echo "  Component may be specified as vincetrack/vincecomm/kb, or direct name."
}

TSINPUTSTR="%Y%M%dT%H:%M:%S"


while getopts ":s:e:l:" o; do
    case "${o}" in
        s)
            start_ts="--start-time $(($(date -j -f ${TSINPUTSTR} "+%s" ${OPTARG})*1000))"
            ;;
        e)
            end_ts="--end-time $(($(date -j -f ${TSINPUTSTR} "+%s" ${OPTARG})*1000))"
            ;;
        l)
            limit="--limit ${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

shift $((OPTIND -1))

environment=$1;shift
if [ "X${environment}" = "X" ]; then
    usage
    exit 1
fi

component=$1;shift
case "${component}" in
    vincetrack)
        component="vince"
        ;;
    vincecomm)
        component="vinny"
        ;;
    kb)
        component="vincepub"
        ;;
    "")
        usage
        exit 1
        ;;
    *)
        # leave component as user-specified
        ;;
esac

#  aws logs get-log-events --log-group-name bigvince-dev-logging --log-stream-name 'vince' | jq -r .events[].message
aws logs get-log-events --log-group-name ${environment}-logging --log-stream-name ${component} ${start_ts} ${end_ts} ${limit} | jq -r .events[].message
