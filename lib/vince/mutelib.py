from django.contrib.auth.models import User,Group
from vinny.views import VinceProfile as vp
from vinny.models import Case, CaseVulnerability, CaseMemberStatus, CaseMember


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

def mute_case_not_affected(case_id,interactive=False):
    """ Mute case for all users who are participating in a Case but
    have already indicated that they are "Not Affected" - the assumption
    is they do not want to hear about this Case any more due to their
    status being "Not Affected"
    """
    c = Case.objects.get(id=int(case_id))
    if not c:
        if interactive:
            print("No Case found in VinceComm")
        return -1
    vul = CaseVulnerability.objects.filter(case=c)
    if not vul:
        if interactive:
            print("No Vulnerabilities for this Case found in VinceComm")
        return -1
    x = CaseMemberStatus.objects.filter(vulnerability__in=vul,status=2)
    f = CaseMember.objects.filter(id__in=x.values_list('member'))
    user_list = User.objects.using('vincecomm').filter(groups__in=f.values_list('group'))
    t = 'muted_cases'
    updated = 0
    for q in user_list:
        l = vp.objects.get(user=q)
        d = q.vinceprofile.settings.copy()
        if t in d and case_id in d[t]:
            if interactive:
                print(f"Already muted {case_id} {q}")
            continue
        else:
            if t in d:
                if interactive:
                    print(f"Adding to muted_cases {q}")
                d[t] += [case_id]
            else:
                if interactive:
                    print(f"Creating a new muted_case for user {q}")
                d[t] = [case_id]
        l._set_settings(d)
        l.save()
        updated = updated + 1
    return updated

