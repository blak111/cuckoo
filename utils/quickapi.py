#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import tempfile
import hashlib
import sqlite3
import json

logging.basicConfig()
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "../"))

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.bottle import route, run, static_file, redirect, request, error

cfg = Config(cfg=os.path.join(os.path.dirname(__file__), "quickapi.conf"))

# This directory will be created in $tmppath (see store_and_submit)
TMPSUBDIR = "cuckoo-api"
BUFSIZE = 1024

'''
code to submit to the sandbox - from web.py
'''
def store_and_submit_fileobj(fobj, filename, package="", options="", timeout=0, priority=1, machine="", platform=""):
    # Do everything in tmppath/TMPSUBDIR
    tmppath = tempfile.gettempdir()
    targetpath = os.path.join(tmppath, TMPSUBDIR)
    if not os.path.exists(targetpath): os.mkdir(targetpath)

    # Upload will be stored in a tmpdir with the original name
    tmpdir = tempfile.mkdtemp(prefix="upload_", dir=targetpath)
    tmpf = open(os.path.join(tmpdir, filename), "wb")
    t = fobj.read(BUFSIZE)

    # While reading from client also compute md5hash
    md5h = hashlib.md5()
    while t:
        md5h.update(t)
        tmpf.write(t)
        t = fobj.read(BUFSIZE)

    tmpf.close()

    # Submit task to cuckoo db
    db = Database()
    task_id = db.add(file_path=tmpf.name,
                     md5=md5h.hexdigest(),
                     package=package,
                     timeout=timeout,
                     options=options,
                     priority=priority,
                     machine=machine,
                     platform=platform)

    return task_id

'''
lists all of the tasks
'''
@route("/listtasks/<apikey>")
def listtasks(apikey):
    db = Database()
    context = {}

    # API key check
    if not isValidKey(apikey):
        context["error_apikey"] = "Invalid API Key"
        return json.dumps(context)

    try:
        db.cursor.execute("SELECT * FROM tasks " \
                          "ORDER BY status, added_on DESC;")
    except sqlite3.OperationalError as e:
        context["error"] = "Could not load tasks from database."
        return json.dumps(context)


    rows = db.cursor.fetchall()
    
    context['jobs'] = rows

    return json.dumps(context)


'''
handles a new task submission
'''
@route("/submit/<apikey>", method="POST")
def submit(apikey):
    context = {'error':False}
    
    # Optional, can be empty
    package  = request.forms.get("package", "")
    options  = request.forms.get("options", "")
    priority = request.forms.get("priority", 1)
    timeout  = request.forms.get("timeout", "")
    data = request.files.file
    
    # Convert priority
    try:
        priority = int(priority)
    except:
        return errorJson('invalid_priority','priority must be a number')

    # File mandatory
    if data == None or data == "":
        return errorJson('no_file','A file must be submitted for analysis')

    # API key check
    if not isValidKey(apikey):
        return errorJson('invalid_apikey','Invalid API key')
    
    # Finally real store and submit
    taskid = store_and_submit_fileobj(data.file,data.filename, timeout=timeout, priority=priority, options=options, package=package)

    # Show result
    context['taskid'] = taskid
    return json.dumps(context)

'''
returns the status of a given task. also returns number of jobs ahead of it with the jobs_ahead value
'''
@route("/getstatus/<apikey>/<task_id>")
def getstatus(apikey,task_id):
    context = {'error':False}
    
    # API key check
    if not isValidKey(apikey):
        return errorJson('invalid_apikey','Invalid API key')

    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return errorJson('invalid_taskid', 'The specified task ID is invalid')
        
    db = Database()

    try:
        db.cursor.execute("SELECT * FROM tasks where id="+str(int(task_id))+ \
                          " ORDER BY status, added_on DESC;")
    except sqlite3.OperationalError as e:
        return errorJson('db_error','Could not connect to DB')
    
    rows = db.cursor.fetchall()
    
    if rows.__len__() != 1:
        return errorJson('invalid_taskid', 'The specified task ID is invalid')

    context = rows[0]
    context['jobs_ahead'] = getPosition(task_id)
    return json.dumps(context)

    
'''
returns a report for a task or all reports if the filename isn't specified
'''
@route("/getreports/<apikey>/<task_id>/<report>")
@route("/getreports/<apikey>/<task_id>")
def getreports(apikey,task_id,report=False):
    context = {'error':False}

    # API key check
    if not isValidKey(apikey):
        return errorJson('invalid_apikey','Invalid API key')
    
    db = Database()
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return errorJson('invalid_taskid', 'The specified task ID is invalid')    
    
    #check if task is complete
    if not isTaskComplete(task_id):
        return errorJson('analysis_incomplete','Analysis for that task is not complete')

    report_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports")
    # Check if the HTML report exists
    if not os.path.exists(report_dir):
        return errorJson('error_reportdir','Could not open the report directory')

    context['reports']={}
    reportfound = False
    for filename in os.listdir(report_dir):
        if not report or report == filename:
            reportfound = True
            context['reports'][filename] = open(os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", filename), "rb").read()

    if not reportfound:
        if not report:
            return errorJson('report_not_found','No reports were found for that task')
        else:
            return errorJson('report_not_found','No reports were found with the name "'+report+'"')
    # Return content of the report(s)
    return json.dumps(context)

'''
returns an error code and description in a standard format
'''
def errorJson(errorcode,errormessage):
    error = {'error':True, 'error_code':errorcode,'error_message':errormessage }
    return json.dumps(error)

'''
returns the number of tasks ahead of the given task with the same priority
'''    
def getPosition(task_id):
    db = Database()
    db.cursor.execute("SELECT * FROM tasks where added_on<(select added_on from tasks where id="+str(int(task_id))+")" \
                          "and status=0 and priority=(select priority from tasks where id="+str(int(task_id))+") ORDER BY status, added_on DESC;")
    return db.cursor.fetchall().__len__()

'''
return true if task is finished, else false
'''    
def isTaskComplete(task_id):
    if not task_id.isdigit():
        return False
    db = Database()

    try:
        db.cursor.execute("SELECT * FROM tasks where id="+str(int(task_id))+ \
                          " ORDER BY status, added_on DESC;")
    except sqlite3.OperationalError as e:
        return False
    
    rows = db.cursor.fetchall()
    
    if rows.__len__() != 1:
        return False

    for row in rows:
        if row['status']==2:
            return True
        
    return False
    
'''
Determine if API Key is valid
'''
def isValidKey(key):
    if key in keys:
        return True
    return False

'''
catch some request errors
'''
@error(404)
@error(403)
def httperror(code):
    return errorJson('request_error','invalid API request')    


'''
start from here
'''    
if __name__ == "__main__":
    ##load up options from config file
    access = getattr(cfg, 'access')
    network = getattr(cfg, 'network')
    keys = access['apikeys'].strip().split(',')

    run(host=network['address'], port=int(network['port']), debug=True, reloader=True)