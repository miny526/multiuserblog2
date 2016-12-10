import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db
# from google.appengine.api import users

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = "minyoungssecret"

#render_str() made a global function since render() within the Post class needs to call render_str() as well
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val=secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	#Prevents having to type self.response.out all the time
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

    #takes a template name and some dictionary of parameters, things to substitute into the template
	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

    #calls write and render_str to print out a template
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	#Sets a cookie. Calls make_secure_val on val and stores that in a cookie
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; path=/' % (name, cookie_val))

	#Give it a name, and it finds that cookie in the request. 
	#if the cookie exists and it passes check_secure_val, return cookie_val
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	#Sets a secure cookie, user id and it equals the user's id
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	#Sets the cookie to nothing
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	#Optional if you want to show different pages for those who are logged in. 
	#Check for the user cookie called user_id. If it exists, store in self.user
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))



def render_post(response, post):
	response.out.write('<b>' + post.subject +'</b><br>')
	response.out.write(post.content)

class MainPage(Handler):
	def get(self):
		self.render('base.html')




######ENCRYPTION


def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

#Takes username, password and optional parameter for salt. Returns salt, hashed name, pw and salt.
#What we store in the database
def make_pw_hash(name, pw, salt = None):
	if not salt: 
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h ==make_pw_hash(name, password, salt)

#creates the ancestor element in the database to store all users
def users_key(group = "default"):
	return db.Key.from_path('users', group)



#db.Model makes it a data store object.
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	#decorator. You can call this method on this object
	#You can call User.by_id to get User.get_by_id, which is built into the datastore
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent=users_key())

	#same thing as "select * from user, where name = name"
	@classmethod
	def by_name(cls, name):
		print name
		u = User.all().filter('name =', name).get()
		print u
		return u

	#Cretaes a new user object, but doesn't store in the database yet. 
	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
			name = name,
			pw_hash = pw_hash, 
			email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		# if u and valid_pw(name, pw, u.pw_hash):
		if u:
			return u


######BLOG STUFF
#Defines a single blog and facilitate multiple blogs on the same site
def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	#properties that a blog entry has
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	user_id = db.IntegerProperty(required = True)

	#renders that blog entry. We'll be rendering in HTML but user doesn't type in HTML for the most part.
	##we want users to be able to type in new lines in the textbox
	def render(self):
		#replaces new lines in the input text into HTML line breaks.
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

#handler for /blog
class BlogFront(Handler):
	def get(self):
		#Looks up all of the posts ordered by creation time and stores them in the post object
		posts = Post.all().order('-created')
		#posts = db.GqlQuery("select * from Post order by created desc")
		#renders the fromt.html template w/ this query, the result of this query, and variable posts
		self.render('front.html', posts = posts)

#page for a particular post
class PostPage(Handler):
	def get(self, post_id):
		#first step in looking up a particular post in Google datastore
		##Find the post with the ID post_id, which gets passed in from the URL whose parent is blog_key
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		#storing key in post
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(Handler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect('/blog/login')

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent=blog_key(), subject=subject, content=content, user_id=self.user.key().id())
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "Please enter both subject and content"
			self.render("newpost.html", subject=subject, content=content, error=error)


#### USER AUTHENTICATION STUFF
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error=False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username=self.username, email=self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That's not a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords don't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

class Unit2Signup(Signup):
	def done(self):
		self.redirect('blog/signup/welcome?username=' + self.username)

class Register(Signup):
	def done(self):
		u = User.by_name(self.username)
		if u:
			msg = "That username already exists"
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/blog/login/welcome')




class Login(Handler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		#self.login different function from User.login. Two different login functions
		#.login here is referring to login function under User class
		u = User.login(username, password)
		#.login here is referring to login function defined under Handler
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			msg = "Invalid login"
			self.render('login-form.html', error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog')

class LogoutConfirm(Handler):
	def get(self):
		self.render('logoutconfirm.html')

#Unit2 Welcome
class RegisteredWelcome(Handler):
	def get(self):
		username = self.request.get('username')
		if valid_username(username):
			self.render('welcome.html', username=username)
		else:
			self.redirect('/blog/signup')

#Unit3 Welcome
class LoginWelcome(Handler):
	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/blog/signup')


# class Author(db.Model):
# 	name = db.StringProperty()


# class Story(db.Model):
# 	author = db.ReferenceProperty(Author)
# 	story = db.get(story_key)
# 	author_name = story.author.name

#######EDITING, COMMENTING AND DELETING
class EditPost(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			#Gets the post data based on what is passed from post_id into key
			post = db.get(key)
			if post and post.user_id==self.user.key().id():
				self.render('editpost.html', p=post)
			else:
				error1 = "Only the author of this post can edit/delete."
				error2 = "Please log out to change user."
				self.render('logoutconfirm.html', error1=error1, error2=error2)
		else:
			error="You must log in to continue"
			self.render('login-form.html', error = error)

	def post(self, post_id):
		subject = self.request.get('subject')
		content = self.request.get('content')
		if subject and content:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			post.subject = subject
			post.content = content
			post.put()
			self.redirect('/blog/%s' % post_id)

		else:
				error = "Please enter both subject and content"
				self.render('post.html', p=post)


class DeletePost(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)

			if post and post.user_id==self.user.key().id():
				self.render('deletepost.html', p=post)
			else:
				error1 = "Only the author of this post can edit/delete."
				error2 = "Please log out to change user."
				self.render('logoutconfirm.html', error1=error1, error2=error2)

		else:
			error = "You must log in to continue"
			self.render('login-form.html', error = error)

	def post(self, post_id):
		subject = self.request.get('subject')
		content = self.request.get('content')
		username = self.request.get('username')

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		post.delete()
		self.render('deleteconfirm.html')
		# self.redirect('/blog')


class AboutMe(Handler):
	def get(self):
		self.render('aboutme.html')


def get(self):
		self.render('login-form.html')

def comment_key(name = "default"):
	return db.Key.from_path('comments', name)

class Comment(db.Model):
	comment = db.StringProperty(required=True)
	post = db.ReferenceProperty(Post)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now = True)
	user_id = db.StringProperty(required=True)

	def render(self):
		self._render_text=self.comment.replace('\n', '<br>')
		return render_str('comment.html', c = self)

class NewComment(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			comments=Comment.all().order('-created')
			if post:
				self.render('comment.html', post=post)
		else:
			error = "You must log in to continue"
			self.render('login-form.html', error=error)

	def post(self, post_id):
		comment = self.request.get('comment')
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if comment:
			c = Comment(parent=comment_key(), post=post, comment=comment, user_id=str(self.user.key().id()))
			c.put()
			self.redirect('/blog/%s' % str(post.key().id()))
		else:
			error = "Comment cannot be blank"
			self.render('comment.html', comment=comment, error=error)




app = webapp2.WSGIApplication([('/', MainPage),
	('/blog/unit2/signup', Unit2Signup),
	('/blog/login/welcome', LoginWelcome),
	('/blog/?', BlogFront),
	('/blog/([0-9]+)', PostPage),
	('/blog/newpost', NewPost),
	('/blog/signup', Register),
	('/blog/signup/welcome', RegisteredWelcome),
	('/blog/login', Login),
	('/blog/logout', Logout),
	('/blog/logout/confirm', LogoutConfirm),
	('/blog/editpost/([0-9]+)', EditPost),
	('/blog/deletepost/([0-9]+)', DeletePost),
	('/blog/aboutme', AboutMe),
	('/blog/comment/([0-9]+)', NewComment)],
	debug = True)

 













