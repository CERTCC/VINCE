#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################
import logging
import os
from django.conf import settings
from django.contrib.auth.models import User, Group
from vinny.models import (
    VinceCommEmail,
    GroupContact,
    Case,
    Post,
    PostRevision,
    CaseMember,
    CaseVulnerability,
    CaseTracking,
    VinceCommGroupAdmin,
    CaseMemberUserAccess,
    VCDailyNotification,
    Message,
    VINCEEmailNotification,
)
from django.contrib.auth.models import User, Group
import boto3
from bs4 import BeautifulSoup
from lib.vince import markdown_helpers
from vinny.mailer import (
    send_user_mention_notification,
    send_group_mention_notification,
    send_post_notification,
    send_daily_digest_mail,
    send_newmessage_mail,
)
import traceback

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def user_is_admin(contact, user):
    return VinceCommGroupAdmin.objects.filter(contact=contact, email__email=user.email).exists()


def user_has_access(case, user):
    return CaseMemberUserAccess.objects.filter(casemember=case, user=user).exists()


def send_comm_worker_msg_all(to, subject, content, from_user, from_group):

    try:
        client = boto3.client("sns", settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_COMM_SNS_ARN,
            Subject="Send message notifications",
            Message="message notify all",
            MessageAttributes={
                "MessageType": {
                    "DataType": "String",
                    "StringValue": "MessageNotifyAll",
                },
                "Message": {"DataType": "String", "StringValue": content},
                "Subject": {"DataType": "String", "StringValue": subject},
                "To_group": {"DataType": "String", "StringValue": to},
                "From_User": {"DataType": "String", "StringValue": str(from_user)},
                "From_Group": {"DataType": "String", "StringValue": str(from_group)},
            },
        )

        logger.debug(f"In send_comm_worker_msg_all Response:{response}")
    except:
        logger.debug(f"Error in send_comm_worker_msg_all {traceback.format_exc()}")


def send_comm_worker(post=None, message=None):
    try:
        client = boto3.client("sns", settings.AWS_REGION)

        if post:
            response = client.publish(
                TopicArn=settings.VINCE_COMM_SNS_ARN,
                Subject="Send post notifications",
                Message="post notify",
                MessageAttributes={
                    "MessageType": {
                        "DataType": "String",
                        "StringValue": "PostNotify",
                    },
                    "Post": {"DataType": "String", "StringValue": str(post.id)},
                },
            )
        elif message:
            response = client.publish(
                TopicArn=settings.VINCE_COMM_SNS_ARN,
                Subject="Send message notifications",
                Message="message notify",
                MessageAttributes={
                    "MessageType": {
                        "DataType": "String",
                        "StringValue": "MessageNotify",
                    },
                    "Message": {"DataType": "String", "StringValue": str(message.id)},
                },
            )

        logger.debug(f"In send_comm_worker Response:{response}")
    except:
        logger.debug(f"Error in send_comm_worker {traceback.format_exc()}")


def vince_comm_send_sqs(msgtype, table, case, user, group, body, queue="Inbox", message=None):
    if group == None:
        group = "None"
    if message == None:
        message = "None"

    try:
        client = boto3.client("sns", settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_TRACK_SNS_ARN,
            Subject=msgtype,
            Message=body,
            MessageAttributes={
                "MessageType": {
                    "DataType": "String",
                    "StringValue": msgtype,
                },
                "Group": {"DataType": "String", "StringValue": group},
                "Table": {"DataType": "String", "StringValue": table},
                "Case": {"DataType": "String", "StringValue": case},
                "User": {"DataType": "String", "StringValue": user},
                "Queue": {"DataType": "String", "StringValue": queue},
                "Message": {"DataType": "String", "StringValue": str(message)},
            },
        )

        logger.debug(f"In vince_comm_send_sqs Response:{response}")
    except:
        send_sns("sending to update queue", "send_sns_json failed", traceback.format_exc())
        logger.debug(f"Error in vince_comm_send_sqs {traceback.format_exc()}")


def get_vince_track_users():
    return User.objects.filter(groups__name="vincetrack")


def update_post(data):

    case = Case.objects.filter(vuid=data["case"]).first()

    # do we have this post already?
    post = Post.objects.filter(case=case, vince_id=data["pk"]).first()
    if post:
        rev = PostRevision()
        rev.inherit_predecessor(post)
        rev.content = data["content"]
        rev.deleted = False
        rev.user = User.objects.filter(username=data["user"]).first()
        post.add_revision(rev)
    else:
        post = Post(
            case=case, author=User.objects.filter(username=data["user"]).first(), pinned=True, vince_id=data["pk"]
        )
        post.save()
        post.add_revision(PostRevision(content=data["content"]), save=True)


def add_participant_case(data):

    case = Case.objects.filter(vuid=data["case"]).first()

    username = data["user"]

    user = User.objects.filter(username=username).first()

    if user:
        # find generic vul group
        group = Group.objects.filter(name=data["case"]).first()
        if group:
            group.user_set.add(user)
        else:
            group = Group(name=data["case"])
            group.save()
            group.user_set.add(user)

        try:
            member = CaseMember(
                case=case, group=group, participant=user, user=User.objects.filter(username=data["user_added"]).first()
            )
            member.save()
        except:
            logger.debug(f"In add_participant_case Member already exists")


def add_vendor_case(data):

    case = Case.objects.filter(vuid=data["case"]).first()

    for vendor in data["vendor_list"]:
        contact = Contact.objects.filter(id=vendor).first()

        if contact:
            # search GroupContact
            group = GroupContact.objects.filter(contact=contact).first()
            if group == None:
                # make sure group doesn't exist already
                oldgroup = Group.objects.filter(name=contact.vendor_name).first()
                if oldgroup:
                    group = oldgroup
                else:
                    group = Group(name=contact.vendor_name)
                    group.save()

                gc = GroupContact(group=group, contact=contact)
                gc.save()
                group = gc

            member = CaseMember.objects.filter(case=case, group=group.group).first()
            if member:
                # vendor already exists
                pass
            else:
                member = CaseMember(
                    case=case, group=group.group, user=User.objects.filter(username=data["user"]).first()
                )
                member.save()

        else:
            logger.debug(f"In add_vendor_case MAJOR PROBLEM - We don't have this contact. SEND AN ALERT")


def add_vul_case(data):

    case = Case.objects.filter(vuid=data["vuid"]).first()

    # do we have this post already?
    vul = CaseVulnerability.objects.filter(case=case, vince_id=data["pk"]).first()

    if vul:
        vul.cve = data["cve"]
        vul.description = data["description"]
        vul.save()
    else:
        vul = CaseVulnerability(case=case, vince_id=data["pk"], description=data["description"], cve=data["cve"])
        vul.save()


def vendor_logged_in(case, member, username):

    if member.participant:
        st = "Participant"
    else:
        st = "Vendor"

    body = "%s %s (user %s) viewed case %s" % (st, member.group.name, username, case.vuid)
    vince_comm_send_sqs("VendorLogin", "VulnerableVendor", case.vuid, username, member.group.name, body)


def new_track_ticket(queue, subject, message, case, user, group="None"):

    if case:
        vuid = case.vuid
        table = "Case"
    else:
        vuid = "None"
        table = "Ticket"

    vince_comm_send_sqs("NewTicket", table, vuid, user, group, subject, queue, message)


def send_sns(vul_id, issue, error):
    subject = "Problem with %s for %s" % (issue, vul_id)
    try:
        client = boto3.client("sns", settings.AWS_REGION)
        response = client.publish(TopicArn=settings.VINCE_ERROR_SNS_ARN, Subject=subject, Message=error)
        logger.debug(f"In send_sns Response:{response}")
    except Exception as e:
        logger.debug(f"Exception in send_sns Error is {e}")


def send_sns_json(form, subject, message):
    try:
        client = boto3.client("sns", settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_TRACK_SNS_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes={"ReportType": {"DataType": "String", "StringValue": form}},
        )
        logger.debug(f"In send_sns_json Response:{response}")
    except Exception as e:
        send_sns("publishing json", "send_sns_json failed", traceback.format_exc())
        logger.debug(f"Exception in send_sns Error is {e}")


def get_usernames_from_md(text):
    """Returns a unique usernames set from a text"""
    usernames = set()
    html_text = markdown_helpers.markdown(text)
    logger.debug(f"In get_usernames_from_md, HTML text is {html_text}")
    soup = BeautifulSoup(html_text, "html.parser")
    for mention in soup.select("a.user-mention"):
        logger.debug(f"In get_usernames_from_md mention is {mention} and text is {mention.get_text()}")
        usernames.add(mention.get_text().replace("@", ""))
    return usernames


def user_in_case(user, case):
    groups = user.groups.all()
    if not groups:
        return False
    user_group = groups.values_list("id", flat=True)
    if user.is_staff:
        return True
    else:
        members = CaseMember.objects.filter(case__id=case, group__in=user_group)
        for member in members:
            # here is where it gets complicated -
            # does this vendor allow all users to have acess to the case?
            try:
                # does this user have an active email?
                # emails = member.group.groupcontact.contact.get_emails()
                # if user.email not in emails:
                #    continue

                if member.group.groupcontact.default_access:
                    return True
                # else is this a group admin?
                elif user_is_admin(member.group.groupcontact.contact, user):
                    return True
                elif user_has_access(member, user):
                    return True
            except GroupContact.DoesNotExist:
                # this is a participant/reporter
                return True
    return False


def create_mail_notice(user, case=None, summary=False):

    email = VINCEEmailNotification(user=user, case=case, summary=summary)
    email.save()


def send_usermention_notification(post, text):
    usernames = get_usernames_from_md(text)
    emails_sent = []
    vt_groups = list(GroupContact.objects.filter(vincetrack=True).values_list("contact__vendor_name", flat=True))
    logger.debug(f"In get_usernames_from_md the VT Groups are {vt_groups}")
    for username in usernames:
        u = User.objects.filter(vinceprofile__preferred_username=username).first()
        if u:
            if not (user_in_case(u, post.case.id)):
                logger.debug(f"{username} was tagged, but they aren't in this case {post.case.vu_vuid}")
                continue
            # if u.vinceprofile.settings.get('email_tags'):
            send_user_mention_notification(u, post.author.vinceprofile.preferred_username, post)
            create_mail_notice(u, post.case)
            emails_sent.append(u.email)
        # Check for group names
        if username in vt_groups:
            # don't send to vincetrack users
            continue
        g = GroupContact.objects.filter(contact__vendor_name__istartswith=username).first()
        if g:
            # is this group in this case?
            if not (CaseMember.objects.filter(group=g.group, case=post.case).exists()):
                logger.debug(f"{username} was tagged, but they aren't in this case {post.case.vu_vuid}")
                continue
            # users in group
            users = User.objects.filter(groups=g.group)
            tracking = CaseTracking.objects.filter(case=post.case, group=g.group).first()
            if tracking:
                track_id = tracking.tracking
            else:
                track_id = None
            for u in users:
                if user_in_case(u, post.case.id):  # and u.vinceprofile.settings.get('email_tags'):
                    send_group_mention_notification(
                        u, g.contact.vendor_name, post.author.vinceprofile.preferred_username, post, tracking=track_id
                    )
                    create_mail_notice(u, post.case)
                    emails_sent.append(u.email)
    return emails_sent


def _user_role_for_case(user, case):

    # is this user a coordinator or reporter
    cm = CaseMember.objects.filter(case=case, participant=user).first()
    if cm:
        if cm.coordinator:
            return 2
        return 3

    user_groups = user.groups.exclude(groupcontact__isnull=True)
    cm = CaseMember.objects.filter(case=case, group__in=user_groups).first()
    if cm:
        if cm.coordinator:
            return 2
        elif cm.reporter_group:
            return 3
        else:
            # vendor
            return 4

    return 0


def create_post_notification(post, user, tracking):

    obj, created = VCDailyNotification.objects.update_or_create(
        user=user, case=post.case, defaults={"tracking": tracking}
    )
    if created:
        return
    else:
        obj.posts = obj.posts + 1
        obj.save()


def get_user_preferences(post, user, role, tracking=None):

    # if email notifications disabled.  email notifications disabled is
    # indicated by condition (email_function == "EMAIL")
    user_groups = user.groups.exclude(groupcontact__isnull=True)
    cm = (
        CaseMember.objects.filter(case=post.case, group__in=user_groups)
        .exclude(group__groupcontact__isnull=True)
        .first()
    )
    if cm:
        email = VinceCommEmail.objects.filter(email=user.email, contact=cm.group.groupcontact.contact).first()
        if email and email.email_function == "EMAIL":
            # if notifications are disabled just return false.
            # dont send anything to this user.
            return False

    # does this user have email notifications enabled
    if role != 1:
        # this is pinned, everyone gets it
        if user.vinceprofile.settings.get("muted_cases"):
            muted_cases = user.vinceprofile.settings["muted_cases"]
            if post.case.id in muted_cases:
                # this user has muted the case
                return False

    # if role is 1, post is pinned - everyone gets it
    if role == 2:
        # this is a coordinator non-pinned post
        s = user.vinceprofile.settings.get("email_coordinator_activity", True)
        if s == False:
            return False
    elif role == 3:
        # this is a reporter post
        s = user.vinceprofile.settings.get("email_reporter_activity", True)
        if s == False:
            return False
    else:
        # this is a vendor or other generic post
        s = user.vinceprofile.settings.get("email_all_activity", True)
        if s == False:
            return False

    # does this user have daily notifications setup?
    s = user.vinceprofile.settings.get("email_daily", 1)
    if int(s) == 2:
        # yes, send once daily
        logger.debug(f"Sending daily digest sent for {user.username} according to preference")
        create_post_notification(post, user, tracking)
        return False

    return True


def send_post_email(post, emails):
    participants = CaseMember.objects.filter(case=post.case)
    # don't spam author of post
    emails.append(post.author.email)
    # also don't spam vincetrack users bc they will get track notifications
    vt_users = User.objects.using("vincecomm").filter(groups__name="vincetrack")
    for user in vt_users:
        emails.append(user.email)

    if post.pinned:
        role = 1
    else:
        role = _user_role_for_case(post.author, post.case)

    sent_emails = []
    for u in participants:
        if u.participant:
            if (u.participant.email not in emails) and (u.participant.email not in sent_emails):
                pref = get_user_preferences(post, u.participant, role)
                if pref == False:
                    sent_emails.append(u.participant.email)
                    continue
                try:
                    send_post_notification(post, u.participant, role=role)
                except Exception as e:
                    logger.debug(
                        f"Failure in sending post notification error generated is {e} for user {u.participant}"
                    )
                    send_sns("sending post notification email", "email failed", traceback.format_exc())
                sent_emails.append(u.participant.email)
                create_mail_notice(u.participant, post.case)
        elif u.group:
            tracking = CaseTracking.objects.filter(case=post.case, group=u.group).first()
            if tracking:
                track_id = tracking.tracking
            else:
                track_id = None
            for us in u.group.user_set.all():
                if not (user_in_case(us, post.case.id)):
                    continue

                if us.vinceprofile.service:
                    # is this a service account?  Check if it is supposed to get emails
                    # if the email function is in "TO" or "CC" then yes, send the email
                    if VinceCommEmail.objects.filter(
                        email=us.email, contact=u.group.groupcontact.contact, email_function__in=["EMAIL", "REPLYTO"]
                    ).exists():
                        continue

                if (us.email not in emails) and (us.email not in sent_emails):
                    pref = get_user_preferences(post, us, role, track_id)
                    if pref == False:
                        # don't double email
                        sent_emails.append(us.email)
                        continue
                    try:
                        send_post_notification(post, us, track_id, role=role)
                    except Exception as e:
                        send_sns("sending group notification email", "email failed", traceback.format_exc())
                        logger.debug(f"Failure in sending post notification for {us}, error is {e}")
                    sent_emails.append(us.email)
                    create_mail_notice(us, post.case)


def send_vc_daily_digest(user):

    text = ""

    cases = []
    n = VCDailyNotification.objects.filter(user=user)

    s = user.vinceprofile.settings.get("email_preference", 1)
    if int(s) == 1:
        html = True
    else:
        html = False

    for c, x in enumerate(n, start=1):
        if html:
            text = text + f'<a href="{settings.KB_SERVER_NAME}{x.case.get_absolute_url()}">{x}</a><br/>'
        else:
            text = text + f"{x}[{c}]\r\n"
            cases.append(x.case.get_absolute_url())
        # once we got the text - remove it
        x.delete()

    # add links
    if not (html):
        text = text + "\r\n"
        for c, x in enumerate(cases, start=1):
            text = text + f"[{c}] {settings.KB_SERVER_NAME}{x}\r\n"

    send_daily_digest_mail(user, text)
    create_mail_notice(user, None, True)


def send_message_to_all_group(to_group, subject, content, from_user, from_group):

    if to_group == "1":
        # get all vendors = get all groups with contacts
        groups = Group.objects.all().exclude(groupcontact__contact__isnull=True)
        vendor_groups = groups.exclude(groupcontact__contact__vendor_type="Contact")
        to_list = User.objects.filter(is_active=True, groups__in=vendor_groups).distinct()
        to_list_str = "all vendors"
    elif to_group == "2":
        # get all admins
        group_emails = VinceCommGroupAdmin.objects.all().values_list("email__email", flat=True).distinct()
        to_list = User.objects.filter(is_active=True, email__in=group_emails)
        to_list_str = "all group admins"
    elif to_group == "3":
        # get all users
        to_list = User.objects.filter(is_active=True)
        to_list_str = "all users"
    elif to_group == "4":
        # staff
        to_list = User.objects.filter(is_active=True, is_staff=True)
        to_list_str = "all staff"

    # send all messages individually

    for u in to_list:
        try:
            msg = Message.new_message(from_user, [u.id], None, subject, content, False)
            msg.thread.from_group = from_group
            msg.thread.save()
            # signal is disabled above so send email here
            send_newmessage_mail(msg, u)
            create_mail_notice(u)
        except Exception as e:
            logger.warning(f"Error saving message for user {u} error is {e}")
