from flask import g, redirect, render_template, request, url_for

from flask_login import login_user
from redash import settings
from redash.authentication.org_resolving import current_org
from redash.handlers.base import routes
from redash.models import Group, Organization, User, db
from redash.tasks.general import subscribe
from wtforms import BooleanField, Form, PasswordField, StringField, validators
from wtforms.fields.html5 import EmailField


class SetupForm(Form):
    name = StringField("Name", validators=[validators.InputRequired()])
    email = EmailField("Email Address", validators=[validators.Email()])
    password = PasswordField("Password", validators=[validators.Length(6)])
    org_name = StringField("Organization Name", validators=[validators.InputRequired()])
    security_notifications = BooleanField()
    newsletter = BooleanField()


def create_org(org_name, user_name, email, password):
    # Se remueven caracteres especiales y espacios del nombre
    org_name_url = ''.join(e for e in org_name if e.isalnum())
    org_name_url = org_name_url.lower()
    
    default_org = Organization(name=org_name, slug=org_name_url, settings={})
    admin_group = Group(
        name="admin",
        permissions=["admin", "super_admin"],
        org=default_org,
        type=Group.BUILTIN_GROUP,
    )
    default_group = Group(
        name=org_name_url,
        permissions=Group.DEFAULT_PERMISSIONS,
        org=default_org,
        type=Group.BUILTIN_GROUP,
    )

    db.session.add_all([default_org, admin_group, default_group])
    db.session.commit()

    user = User(
        org=default_org,
        name=user_name,
        email=email,
        group_ids=[admin_group.id, default_group.id],
    )
    user.hash_password(password)

    db.session.add(user)
    db.session.commit()

    return default_org, user


@routes.route("/setup", methods=["GET", "POST"])
def setup():
    '''
    if settings.MULTI_ORG and current_org != None:
        index_url = url_for("redash.index", org_slug=current_org.slug, _external=False)
        return redirect(index_url)
    elif current_org != None:
        return redirect("/")
    '''
    form = SetupForm(request.form)
    form.newsletter.data = True
    form.security_notifications.data = True

    if request.method == "POST" and form.validate():
        default_org, user = create_org(
            form.org_name.data, form.name.data, form.email.data, form.password.data
        )

        g.org = default_org
        login_user(user)

        # signup to newsletter if needed
        if form.newsletter.data or form.security_notifications:
            subscribe.delay(form.data)

        return redirect(url_for("redash.index", org_slug=default_org.slug))

    return render_template("setup.html", form=form)
