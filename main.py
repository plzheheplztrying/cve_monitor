'''
Description: Editor's info at the top of the file
Author: p1ay8y3ar
Date: 2021-04-01 23:53:55
LastEditor: p1ay8y3ar
LastEditTime: 2021-04-15 00:13:48
Email: p1ay8y3ar@gmail.com
'''

import requests
from peewee import *
from datetime import datetime
import time
import random
import math

db = SqliteDatabase("cve.sqlite")


class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db


db.connect()
db.create_tables([CVE_DB])


def write_file(new_contents):
    with open("README.md") as f:
        # Remove the title
        for _ in range(7):
            f.readline()

        old = f.read()
    new = new_contents + old
    with open("README.md", "w") as f:
        f.write(new)


def craw_all():
    # This function crawls all CVE-related repositories from 1999 to 2025
    api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page=100&page={}"
    item_list = []
    for i in range(1999, 2026, 1):  # Updated range to 2025
        try:
            reqtem = requests.get(api.format(i, 1)).json()
            total_count = reqtem["total_count"]
            print("Year: {}, Total: {}".format(i, total_count))  # Translated to English
            for_count = math.ceil(total_count / 100) + 1
            time.sleep(random.randint(3, 15))
        except Exception as e:
            print("Error occurred while fetching count", e)  # Translated to English
            continue

        for j in range(1, for_count, 1):
            try:
                req = requests.get(api.format(i, j)).json()
                items = req["items"]
                item_list.extend(items)
                print("Year: {}, Round: {}, Fetched: {}".format(i, j, len(items)))  # Translated to English
                time.sleep(random.randint(3, 15))
            except Exception as e:
                print("Network error occurred", e)  # Translated to English
                continue

    return item_list


def get_info(year):
    # Used for monitoring
    try:
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated".format(year)
        # Request API
        req = requests.get(api).json()
        items = req["items"]

        return items
    except Exception as e:
        print("Network request error occurred", e)
        return None


def db_match(items):
    r_list = []
    for item in items:
        id = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id).count() != 0:
            continue
        full_name = item["full_name"]
        description = item["description"]
        if description == "" or description is None:
            description = 'no description'
        else:
            description = description.strip()
        url = item["html_url"]
        created_at = item["created_at"]
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at
        })
        CVE_DB.create(id=id,
                      full_name=full_name,
                      description=description,
                      url=url,
                      created_at=created_at)

    return sorted(r_list, key=lambda e: e.__getitem__('created_at'))


def update_all():
    sorted_list = craw_all()
    sorted = db_match(sorted_list)
    if len(sorted) != 0:
        print("Updated {} entries".format(len(sorted)))
        sorted_list.extend(sorted)
    newline = ""
    for s in sorted_list:
        line = "**{}** : [{}]({})  create time: {}\n\n".format(
            s["description"], s["full_name"], s["url"], s["created_at"])
        newline = line + newline
    print(newline)
    if newline != "":
        newline = "# Automatic monitor GitHub CVE using GitHub Actions \n\n > Update time: {}  total: {} \n\n".format(
            datetime.now(),
            CVE_DB.select().where(CVE_DB.id != None).count()) + newline

        write_file(newline)


def main():
    # Monitoring function
    year = datetime.now().year
    sorted_list = []
    for i in range(year, 1999, -1):
        item = get_info(i)
        if item is None or len(item) == 0:
            continue
        print("Year {}, Retrieved raw data: {} entries".format(i, len(item)))
        sorted = db_match(item)
        if len(sorted) != 0:
            print("Year {}, Updated {} entries".format(i, len(sorted)))
            sorted_list.extend(sorted)
        count = random.randint(3, 15)
        time.sleep(count)

    newline = ""
    for s in sorted_list:
        line = "**{}** : [{}]({})  create time: {}\n\n".format(
            s["description"], s["full_name"], s["url"], s["created_at"])
        newline = line + newline
    print(newline)
    if newline != "":
        newline = "# Automatic monitor GitHub CVE using GitHub Actions \n\n > Update time: {}  total: {} \n\n \n ![star me](https://img.shields.io/badge/star%20me-click%20--%3E-orange) [CVE Monitor](https://github.com/p1ay8y3ar/cve_monitor)  [Browsing through the web](https://p1ay8y3ar.github.io/cve_monitor/)  ![visitors](https://visitor-badge.glitch.me/badge?page_id=cve_monitor) \n\n".format(
            datetime.now(),
            CVE_DB.select().where(CVE_DB.id != None).count()) + newline

        write_file(newline)


if __name__ == "__main__":
    # update_all()
    main()
