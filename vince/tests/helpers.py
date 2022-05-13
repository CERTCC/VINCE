from vince.models import TicketCC
from vince.forms import TicketForm
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail


FIXTURES = ['auth.json', 'emailtemplate.json', 'TicketQueue_dwight.json']


def addwatchers(ticket):
    tc = TicketCC(ticket=ticket, email='watcher1@w1.org')
    tc.save()
    tc = TicketCC(ticket=ticket, email='watcher2@w2.org')
    tc.save()

def create_ticket(data=None, attachment_file_path=None):
    """
    Create a ticket for testing.
    :param data: Form data
    :param attachment_file_path: path to file to attach
    :return: a Ticket and the Emai'newticket_submitter@exmaple.org
    """
    if not data:
        data = {
            'queue': 1,
            'title': 'Test ticket',
            'body': 'A test ticket',
            'submitter_email': 'newticket_submitter@example.org',
            'priority': '3',
        }

    if attachment_file_path:
        upload_file = open(attachment_file_path, 'rb')
        file_dict = {'attachment': SimpleUploadedFile(upload_file.name, upload_file.read())}
        tf = TicketForm(data, file_dict)
    else:
        tf = TicketForm(data)

    tf.is_valid()
    tf.cleaned_data['queue'] = int(data['queue'])
    test_ticket = tf.save()

    return test_ticket


def get_email():
    emails = []
    for x in mail.outbox:
        emails.append(x)

    mail.outbox.clear()
    return emails


def flatten_emails(l):
    flat = []
    for x in l:
        for y in x.recipients():
            flat.append(y)

    return flat

def get_watchers(ticket):
    return ticket.ticketcc_set
