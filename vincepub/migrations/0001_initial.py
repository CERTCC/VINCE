# Generated by Django 2.2.26 on 2022-01-25 16:42

import bigvince.storage_backends
import django.contrib.postgres.indexes
import django.contrib.postgres.search
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import vincepub.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='GovReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('contact_name', models.CharField(max_length=100)),
                ('contact_org', models.CharField(blank=True, max_length=100, null=True)),
                ('contact_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('contact_phone', models.CharField(blank=True, max_length=20, null=True)),
                ('credit_release', models.BooleanField(default=True)),
                ('affected_website', models.URLField()),
                ('vul_description', models.TextField()),
                ('tracking', models.CharField(blank=True, max_length=100, null=True)),
                ('comments', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='NoteVulnerability',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cve', models.CharField(blank=True, max_length=50, null=True, verbose_name='CVE')),
                ('description', models.TextField(verbose_name='Description')),
                ('uid', models.CharField(max_length=100)),
                ('date_added', models.DateTimeField(default=django.utils.timezone.now)),
                ('dateupdated', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='PrivateDocument',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('upload', models.FileField(storage=bigvince.storage_backends.PrivateMediaStorage(), upload_to='')),
            ],
        ),
        migrations.CreateModel(
            name='Vendor',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('contact_date', models.DateTimeField(help_text='The date that this vendor was first contacted about this vulnerability.')),
                ('vendor', models.CharField(help_text='The name of the vendor that may be affected.', max_length=200)),
                ('references', models.TextField(blank=True, help_text='Vendor references for this case', null=True)),
                ('statement', models.TextField(blank=True, help_text='A general vendor statement for all vuls in the case', null=True)),
                ('dateupdated', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='VendorHTML',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vuid', models.CharField(max_length=20)),
                ('idnumber', models.CharField(max_length=20)),
                ('vendorrecordid', models.CharField(max_length=50)),
                ('statement', models.TextField(blank=True, null=True)),
                ('information', models.TextField(blank=True, null=True)),
                ('urls', models.TextField(blank=True, null=True)),
                ('addendum', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='VendorRecord',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vuid', models.CharField(max_length=20)),
                ('idnumber', models.CharField(max_length=20)),
                ('vendorrecordid', models.CharField(max_length=50)),
                ('vendor', models.CharField(max_length=100)),
                ('status', models.CharField(blank=True, max_length=100, null=True)),
                ('statement', models.TextField(blank=True, null=True)),
                ('vendorinformation', models.TextField(blank=True, null=True)),
                ('vendorurls', vincepub.models.OldJSONField(blank=True, null=True)),
                ('addendum', models.TextField(blank=True, null=True)),
                ('datenotified', models.DateTimeField(blank=True, null=True)),
                ('dateresponded', models.DateTimeField(blank=True, null=True)),
                ('datelastupdated', models.DateTimeField(blank=True, null=True)),
                ('revision', models.IntegerField(default=1)),
            ],
        ),
        migrations.CreateModel(
            name='VendorStatement',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('contact_name', models.CharField(max_length=100)),
                ('contact_title', models.CharField(blank=True, max_length=100, null=True)),
                ('org_name', models.CharField(max_length=100)),
                ('org_email', models.EmailField(max_length=254)),
                ('addl_emails', models.CharField(blank=True, max_length=1000, null=True)),
                ('telephone', models.CharField(blank=True, max_length=20, null=True)),
                ('tracking', models.CharField(blank=True, max_length=100, null=True)),
                ('comments', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='VulCoordRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('contact_name', models.CharField(max_length=100)),
                ('contact_org', models.CharField(blank=True, max_length=100, null=True)),
                ('contact_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('contact_phone', models.CharField(blank=True, max_length=20, null=True)),
                ('share_release', models.BooleanField(default=True)),
                ('credit_release', models.BooleanField(default=True)),
                ('coord_status', models.CharField(max_length=100)),
                ('vendor_name', models.CharField(max_length=100)),
                ('multiplevendors', models.BooleanField()),
                ('other_vendors', models.TextField(blank=True, null=True)),
                ('first_contact', models.DateTimeField(blank=True, null=True)),
                ('vendor_communication', models.TextField(blank=True, null=True)),
                ('product_name', models.CharField(max_length=100)),
                ('product_version', models.CharField(max_length=100)),
                ('vul_description', models.TextField()),
                ('vul_exploit', models.TextField()),
                ('vul_impact', models.TextField()),
                ('vul_discovery', models.TextField()),
                ('vul_public', models.BooleanField(default=False)),
                ('public_references', models.CharField(blank=True, max_length=1000, null=True)),
                ('vul_exploited', models.BooleanField(default=False)),
                ('exploit_references', models.CharField(blank=True, max_length=1000, null=True)),
                ('vul_disclose', models.BooleanField(default=False)),
                ('disclosure_plans', models.CharField(blank=True, max_length=1000, null=True)),
                ('user_file', models.FileField(blank=True, null=True, storage=bigvince.storage_backends.PrivateMediaStorage(), upload_to=vincepub.models.update_filename)),
                ('tracking', models.CharField(blank=True, max_length=100, null=True)),
                ('comments', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='VulnerabilityNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField(verbose_name='vulnote contents')),
                ('title', models.CharField(max_length=512, verbose_name='vul note title')),
                ('references', models.TextField(blank=True, verbose_name='references')),
                ('dateupdated', models.DateTimeField(auto_now=True)),
                ('datefirstpublished', models.DateTimeField(auto_now_add=True)),
                ('revision_number', models.IntegerField(default=1, verbose_name='revision number')),
                ('vuid', models.CharField(max_length=20)),
                ('publicdate', models.DateTimeField(blank=True, null=True)),
                ('published', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='VUReportHTML',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vuid', models.CharField(max_length=50)),
                ('description', models.TextField(blank=True, null=True)),
                ('impact', models.TextField(blank=True, null=True)),
                ('solution', models.TextField(blank=True, null=True)),
                ('systems', models.TextField(blank=True, null=True)),
                ('overview', models.TextField(blank=True, null=True)),
                ('ack', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='VUReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vuid', models.CharField(max_length=50)),
                ('idnumber', models.CharField(max_length=20)),
                ('name', models.CharField(max_length=500)),
                ('keywords', vincepub.models.OldJSONField(blank=True, null=True)),
                ('overview', models.TextField(blank=True, null=True)),
                ('clean_desc', models.TextField(blank=True, null=True)),
                ('impact', models.TextField(blank=True, null=True)),
                ('resolution', models.TextField(blank=True, null=True)),
                ('workarounds', models.TextField(blank=True, null=True)),
                ('sysaffected', models.TextField(blank=True, null=True)),
                ('thanks', models.TextField(blank=True, null=True)),
                ('author', models.CharField(blank=True, max_length=500, null=True)),
                ('public', vincepub.models.OldJSONField(blank=True, null=True)),
                ('cveids', vincepub.models.OldJSONField(blank=True, null=True)),
                ('certadvisory', vincepub.models.OldJSONField(blank=True, null=True)),
                ('uscerttechnicalalert', models.TextField(blank=True, null=True)),
                ('vulnerabilitycount', models.IntegerField(blank=True, null=True)),
                ('datecreated', models.DateTimeField(default=django.utils.timezone.now)),
                ('publicdate', models.DateTimeField(blank=True, null=True)),
                ('datefirstpublished', models.DateTimeField(blank=True, null=True)),
                ('dateupdated', models.DateTimeField(blank=True, null=True)),
                ('revision', models.IntegerField(default=1)),
                ('vrda_d1_directreport', models.CharField(blank=True, max_length=10, null=True)),
                ('vrda_d1_population', models.CharField(blank=True, max_length=10, null=True)),
                ('vrda_d1_impact', models.CharField(blank=True, max_length=10, null=True)),
                ('cam_widelyknown', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_exploitation', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_internetinfrastructure', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_population', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_impact', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_easeofexploitation', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_attackeraccessrequired', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_scorecurrent', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_scorecurrentwidelyknown', models.CharField(blank=True, max_length=15, null=True)),
                ('cam_scorecurrentwidelyknownexploited', models.CharField(blank=True, max_length=15, null=True)),
                ('ipprotocol', models.CharField(blank=True, max_length=50, null=True)),
                ('cvss_accessvector', models.TextField(blank=True, null=True)),
                ('cvss_accesscomplexity', models.TextField(blank=True, null=True)),
                ('cvss_authentication', models.TextField(blank=True, null=True)),
                ('cvss_confidentialityimpact', models.TextField(blank=True, null=True)),
                ('cvss_integrityimpact', models.TextField(blank=True, null=True)),
                ('cvss_availabilityimpact', models.TextField(blank=True, null=True)),
                ('cvss_exploitablity', models.TextField(blank=True, null=True)),
                ('cvss_remediationlevel', models.TextField(blank=True, null=True)),
                ('cvss_reportconfidence', models.TextField(blank=True, null=True)),
                ('cvss_collateraldamagepotential', models.TextField(blank=True, null=True)),
                ('cvss_targetdistribution', models.TextField(blank=True, null=True)),
                ('cvss_securityrequirementscr', models.TextField(blank=True, null=True)),
                ('cvss_securityrequirementsir', models.TextField(blank=True, null=True)),
                ('cvss_securityrequirementsar', models.TextField(blank=True, null=True)),
                ('cvss_basescore', models.TextField(blank=True, null=True)),
                ('cvss_basevector', models.TextField(blank=True, null=True)),
                ('cvss_temporalscore', models.TextField(blank=True, null=True)),
                ('cvss_temporalvector', models.TextField(blank=True, null=True)),
                ('cvss_environmentalscore', models.TextField(blank=True, null=True)),
                ('cvss_environmentalvector', models.TextField(blank=True, null=True)),
                ('metric', models.FloatField(blank=True, null=True)),
                ('keywords_str', models.TextField(blank=True, null=True)),
                ('cve_str', models.TextField(blank=True, null=True)),
                ('search_vector', django.contrib.postgres.search.SearchVectorField(null=True)),
                ('vulnote', models.ForeignKey(blank=True, help_text='This is used for VINCE published Vul Notes', null=True, on_delete=django.db.models.deletion.CASCADE, to='vincepub.VulnerabilityNote')),
            ],
        ),
        migrations.CreateModel(
            name='VendorVulStatus',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.IntegerField(choices=[(1, 'Affected'), (2, 'Unaffected'), (3, 'Unknown')], default=3, help_text='The vendor status. Unknown until vendor says otherwise.')),
                ('date_added', models.DateTimeField(default=django.utils.timezone.now)),
                ('dateupdated', models.DateTimeField(auto_now=True)),
                ('references', models.TextField(blank=True, null=True)),
                ('statement', models.TextField(blank=True, null=True)),
                ('vendor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vendorvulstatus', to='vincepub.Vendor')),
                ('vul', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vincepub.NoteVulnerability')),
            ],
        ),
        migrations.AddField(
            model_name='vendor',
            name='note',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vendors', to='vincepub.VulnerabilityNote'),
        ),
        migrations.AddField(
            model_name='notevulnerability',
            name='note',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vincepub.VulnerabilityNote'),
        ),
        migrations.AddIndex(
            model_name='vureport',
            index=django.contrib.postgres.indexes.GinIndex(fields=['search_vector'], name='vul_gin'),
        ),
        migrations.RunSQL(
            sql="\n            DROP TRIGGER IF EXISTS vureport_update_trigger\n            ON vincepub_vureport;\n            CREATE TRIGGER vureport_update_trigger\n            BEFORE INSERT OR UPDATE of name, overview, clean_desc, author, impact, thanks, resolution, vuid, uscerttechnicalalert, workarounds, search_vector, keywords_str, cve_str\n            ON vincepub_vureport\n            FOR EACH ROW EXECUTE PROCEDURE\n            tsvector_update_trigger(search_vector, 'pg_catalog.english', name, overview, clean_desc, author, impact, thanks, resolution, vuid, uscerttechnicalalert, workarounds, keywords_str, cve_str);\n\n            UPDATE vincepub_vureport SET search_vector = NULL;\n            ",
            reverse_sql='\n            DROP TRIGGER IF EXISTS vureport_update_trigger\n            ON vincepub_vureport;\n            ',
        ),
        migrations.AddField(
            model_name='vureport',
            name='publish',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='govreport',
            name='user_file',
            field=models.FileField(blank=True, null=True, storage=bigvince.storage_backends.VRFReportsStorage(), upload_to=vincepub.models.gov_update_filename),
        ),
        migrations.AlterField(
            model_name='privatedocument',
            name='upload',
            field=models.FileField(storage=bigvince.storage_backends.VRFReportsStorage(), upload_to=''),
        ),
        migrations.AlterField(
            model_name='vulcoordrequest',
            name='user_file',
            field=models.FileField(blank=True, null=True, storage=bigvince.storage_backends.VRFReportsStorage(), upload_to=vincepub.models.update_filename),
        ),
        migrations.AlterField(
            model_name='vureport',
            name='idnumber',
            field=models.CharField(max_length=20, unique=True),
        ),
        migrations.AlterField(
            model_name='vureport',
            name='vuid',
            field=models.CharField(max_length=50, unique=True),
        ),
        migrations.AlterField(
            model_name='vureport',
            name='vulnote',
            field=models.OneToOneField(blank=True, help_text='This is used for VINCE published Vul Notes', null=True, on_delete=django.db.models.deletion.CASCADE, to='vincepub.VulnerabilityNote'),
        ),
        migrations.AddField(
            model_name='vendor',
            name='statement_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='vendor',
            name='contact_date',
            field=models.DateTimeField(blank=True, help_text='The date that this vendor was first contacted about this vulnerability.', null=True),
        ),
        migrations.AddField(
            model_name='vendor',
            name='addendum',
            field=models.TextField(blank=True, help_text='CERT Addendum', null=True),
        ),
        migrations.AlterField(
            model_name='vendorvulstatus',
            name='vul',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notevulnerability', to='vincepub.NoteVulnerability'),
        ),
        migrations.AlterField(
            model_name='notevulnerability',
            name='note',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notevuls', to='vincepub.VulnerabilityNote'),
        ),
        migrations.AlterField(
            model_name='vendorvulstatus',
            name='vul',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vincepub.NoteVulnerability'),
        ),
        migrations.AddField(
            model_name='notevulnerability',
            name='case_increment',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='vendor',
            name='uuid',
            field=models.UUIDField(blank=True, editable=False, help_text='The uuid of the contact in track', null=True),
        ),
        migrations.AlterField(
            model_name='vulnerabilitynote',
            name='references',
            field=models.TextField(blank=True, null=True, verbose_name='references'),
        ),
        migrations.AlterField(
            model_name='vulnerabilitynote',
            name='dateupdated',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name='vendor',
            name='dateupdated',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='vulcoordrequest',
            name='ics_impact',
            field=models.BooleanField(default=False),
        ),
        migrations.DeleteModel(
            name='GovReport',
        ),
        migrations.DeleteModel(
            name='VendorStatement',
        ),
    ]