#!/usr/bin/env python

# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.appengine.api import app_identity
from google.appengine.api import mail
import webapp2
import logging

def send_approved_mail(sender_name, sender_address, recipient_name, recipient_email, subject, msg):
    # [START send_mail]
    # In log, it clearer stated that to actually send mail from dev_appserver.py 
    # you need to locally install and run sendmail, 
    # then run dev_appserver with --enable_sendmail.
    mail.send_mail(sender=sender_address,
                   to=recipient_email,
                   subject=subject,
                   body=msg)
    # [END send_mail]
    return 'Email has been sent to ' + recipient_email


def send_mail_handler(sender_name, recipient_name, recipient_email, subject, msg, **kwargs):

    # Return message from send_approved_mail to main
    return send_approved_mail(sender_name, '{}@appspot.gserviceaccount.com'.format(
        app_identity.get_application_id()), recipient_name, recipient_email,
        subject, msg)
