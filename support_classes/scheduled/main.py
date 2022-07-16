import sys
from time import sleep
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from server_mon_agent import _callerFunc

sys.path.insert(1, '/opt/app-root/src')
from config import SERVER_SECONDS_TASKS_SCHEDULE, SERVER_MINUTES_TASK_SCHEDULE
from support_classes.logging_for_schedulers import logger
from support_classes.scheduled.task_scheduler import check_tasks_in


def main():
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_tasks_in, 'interval', seconds=int(SERVER_SECONDS_TASKS_SCHEDULE),
                      next_run_time=datetime.now())
    scheduler.add_job(_callerFunc, 'interval', minutes=int(SERVER_MINUTES_TASK_SCHEDULE),
                      next_run_time=datetime.now())
    try:
        scheduler.start()
        while True:
            sleep(5)
    except Exception as e:
        logger.error(f"An exception occurred: {e}")
    scheduler.shutdown()


if __name__ == '__main__':
    main()
