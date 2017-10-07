#!/usr/bin/env python

from google.appengine.ext.webapp import template
from google.appengine.ext.ndb import metadata
from google.appengine.ext import ndb

import logging
import os
import os.path
import webapp2
import time

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

from mail import send_mail_handler

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('error403'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

def admin_required(handler):
  """Requires App Engine admin credentials"""
  def check_admin(self, *args, **kwargs):
    auth = self.auth
    user_session = auth.get_user_by_session()
    if user_session:
      if user_session['user_role'] == 'admin':
        return handler(self,*args, **kwargs)
      else:
        self.redirect(self.uri_for('error401'))
  return check_admin

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
    # Get a session store for this request.
    self.session_store = sessions.get_store(request=self.request)

    try:
        # Dispatch the request.
        webapp2.RequestHandler.dispatch(self)
    finally:
        # Save all sessions.
        self.session_store.save_sessions(self.response)

class MainHandler(BaseHandler):
  def get(self):
    self.render_template('home.html')

class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastname')

    all_kinds = ndb.metadata.get_kinds()

    """ First user who sign up will auto assign as 'admin' """
    if u'User' in all_kinds:
      user_role = 'user'
    else:
      user_role = 'admin'

    status = 'active'

    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,
      email_address=email, name=name, password_raw=password,
      last_name=last_name, user_role=user_role, user_status=status, verified=False)

    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (user_name, user_data[1]))
      return
    
    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    sender_name = 'Webapp2UserAccount'
    subject = 'Confirm your registration'
    """ 
    Mail function will be working on GAE,
    so hide the verification_url on GAE.
    """
    if os.environ['APPLICATION_ID'].startswith('dev'):
      # it's localhost
      msg_successful = 'An email has been sent to {email}. Alternatively, \
                      use this link: <a href="{url}">{url}</a>'
    else:
      # it's uploaded on GAE
      msg_successful = 'An email has been sent to {email}.'
    
    msg_fail = 'Sorry, we are unable to send email to you at the moment. \
              Please try again later.'
    msg_email = 'Thank you for creating an account! \
              Please confirm your email address by clicking on the link below: \
              <a href="{url}">{url}</a>'

    """ Call Mail function """
    send_mail = send_mail_handler(sender_name, name, email, subject, msg_email.format(url=verification_url))

    if send_mail:
      self.display_message(msg_successful.format(email=email,url=verification_url))
    else:
      self.display_message(msg_fail.format())
      
class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)
    """ 
    Mail function will be working on GAE,
    so hide the verification_url on GAE.
    """
    if os.environ['APPLICATION_ID'].startswith('dev'):
      msg = 'Send an email to user in order to reset their password. \
            They will be able to do so by visiting <a href="{url}">{url}</a>'
    else:
      msg = 'An email has been sent to you in order to reset their password.'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)

class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)
    
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.display_message('User email address has been verified.')
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)

      """Check if it is banned user"""
      self.curruser = self.user
      if self.curruser.user_status == 'banned':
        self.auth.unset_session()
        raise InvalidAuthIdError()

      self.redirect(self.uri_for('home'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('authenticated-user.html')

class AdminPageHandler(BaseHandler):
  @user_required
  @admin_required
  def get(self):
    self.render_template('authenticated-admin.html')

class AllUsersHandler(BaseHandler):
  @user_required
  @admin_required
  def get(self):
    q_users = self.user_model.query().fetch()
    allusers =[]
    for curruser in q_users:
      u = {}
      keystr = curruser.key.urlsafe()
      u['keystr'] = keystr
      u['username'] = curruser.auth_ids
      u['email_address'] = curruser.email_address
      u['first_name'] = curruser.name
      u['last_name'] = curruser.last_name
      u['user_status'] = curruser.user_status
      u['user_role'] = curruser.user_role
      allusers.append(u)
    params = {
      "allusers" : allusers
    }
    self.render_template('allusers.html', params)

class EditUserHandler(BaseHandler):
  @user_required
  @admin_required
  def get(self):
    pass
  
  @user_required
  @admin_required
  def post(self):
    keystr = self.request.get('keystr')
    post_form = self.request.get('post_form')
    if post_form == 'update':
      self.email_address = self.request.get('email_address')
      self.first_name = self.request.get('first_name')
      self.last_name = self.request.get('last_name')
      self.user_role = self.request.get('user_role')
      self.user_status = self.request.get('user_status')
    curruser = ""
    update_status = ""
    userkey = ndb.Key(urlsafe=keystr)
    user_id = userkey.id()

    curruser = self.user_model.get_by_id(user_id) if user_id else None

    if post_form == 'update':
      curruser.name = self.first_name
      curruser.last_name = self.last_name
      curruser.email_address = self.email_address
      curruser.user_role = self.user_role
      curruser.user_status = self.user_status
      curruser.put()
      update_status = "updated"

    # print(curruser)
    params = {}

    if curruser:
      params = {
        "curruser" : {
          "keystr" : keystr,
          "first_name" : curruser.name,
          "last_name" : curruser.last_name,
          "user_status" : curruser.user_status,
          "email_address" : curruser.email_address,
          "user_role" : curruser.user_role,
          "update_status": update_status
        }
      }
    else:
      params = {
        "curruser" :[{
          "keystr" : "",
          "first_name" : "",
          "last_name" : "",
          "user_status" : "",
          "email_address" : "",
          "user_role" : ""
        }]
      }

    self.render_template('edituser.html', params)

class Error401Handler(BaseHandler):
  def get(self):
    self.render_template('401.html')

class Error403Handler(BaseHandler):
  def get(self):
    self.render_template('403.html')
    #time.sleep(5)
    #self.redirect(self.uri_for('login'))

class Error404Handler(BaseHandler):
  def get(self):
    self.render_template('404.html')

class Error500Handler(BaseHandler):
  def get(self):
    self.render_template('500.html')

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name','user_role', 'user_status']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/authenticated-user', AuthenticatedHandler, name='userpage'),
    webapp2.Route('/authenticated-admin', AdminPageHandler, name='adminpage'), 
    webapp2.Route('/allusers', AllUsersHandler, name='allusers'), 
    webapp2.Route('/edituser', EditUserHandler, name='edituser'), 
    webapp2.Route('/error401', Error401Handler, name='error401'), 
    webapp2.Route('/error403', Error403Handler, name='error403'), 
    webapp2.Route('/error404', Error404Handler, name='error404'), 
    webapp2.Route('/error500', Error500Handler, name='error500')
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
