#!/bin/bash
WORK_DIR="/var/lib/kms-client"
KMS_CLIENT_PID=/var/run/kms-client.pid
SLEEP=5

funcStart() {
    if [ -f "${KMS_CLIENT_PID}" ]; then
        PID=`cat "${KMS_CLIENT_PID}"`
        ps -p $PID >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            ps -f -p $PID
            exit 1
        else
            rm -f "${KMS_CLIENT_PID}" >/dev/null 2>&1
            if [ $? != 0 ]; then
                if [ -w "${KMS_CLIENT_PID}" ]; then
                    cat /dev/null > "${KMS_CLIENT_PID}"
                fi
            fi
        fi
    fi

    nohup ${WORK_DIR}/kms-client 2>&1 >/dev/null &

    if [ ! -z "${KMS_CLIENT_PID}" ]; then
        echo $! > "${KMS_CLIENT_PID}"
    fi
}

funcStop() {
    if [ -f "${KMS_CLIENT_PID}" ]; then
        while [ $SLEEP -ge 0 ]; do
            kill -0 `cat "${KMS_CLIENT_PID}"` >/dev/null 2>&1
            if [ $? -gt 0 ]; then
                rm -f "${KMS_CLIENT_PID}" >/dev/null 2>&1
                if [ $? != 0 ]; then
                    if [ -w "${KMS_CLIENT_PID}" ]; then
                        cat /dev/null > "${KMS_CLIENT_PID}"
                    fi
                fi
                break;
            fi
            if [ $SLEEP -gt 0 ]; then
                sleep 1
            fi
            if [ $SLEEP -eq 0 ]; then
                kill  `cat "${KMS_CLIENT_PID}"`
            fi
            SLEEP=`expr $SLEEP - 1`
        done
    fi
}

if [ "$1" = "start" ] ; then
    funcStart
elif [ "$1" = "stop" ] ; then
    funcStop
elif [ "$1" = "restart" ] ; then
    funcStop
    funcStart
else
  echo "Usage: kms-client.sh ( commands ... )"
  echo "commands:"
  echo "  start             Start KMS Client"
  echo "  stop              Stop KMS Client"
  echo "  restart           Restart KMS Client"
  exit 1

fi

