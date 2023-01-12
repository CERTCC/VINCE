from django.contrib.auth.models import User
from vinny.views import VinceProfile as vp



def mute_user(useremail,case_id,interactive=False):
    """ Mute case for a user with `useremail` identified for a `case_id`
    on success it return 0 (no need to update) or 1. If the user is not
    found or user has nor profile, it returns -ve number repsectively.
    You should use this with try/except block for web/API usage
    """
    q = User.objects.filter(username=useremail).using('vincecomm').first()
    l = vp.objects.filter(user=q).first()
    if not q:
        if interactive:
            print(f"User {useremail} not found")
        return -1
    if not l:
        if interactive:
            print(f"User {useremail} Profile not found")
        return -2 
    d = q.vinceprofile.settings.copy()
    if 'muted_cases' in d:
        if case_id in d['muted_cases']:
            if interactive:
                print(f"Case id {case_id} already muted for {useremail}")
                print(d)
            return 0
        else:
            d['muted_cases'] += [case_id]
    else:
        d['muted_cases'] = [case_id]
    l._set_settings(d)
    l.save()
    if interactive:
        print("Updated profile settings are ")
        print(l._get_settings())
    return 1

