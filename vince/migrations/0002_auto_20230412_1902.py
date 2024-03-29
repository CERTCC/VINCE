# Generated by Django 3.2.17 on 2023-04-12 19:02

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('vince', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Sector',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=75, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='cveallocation',
            name='cve_changes_to_publish',
            field=models.BooleanField(default=True, help_text='Switch to True if changes affected already published cve'),
        ),
        migrations.AlterField(
            model_name='adminpgpemail',
            name='pgp_key_data',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='contact',
            name='vendor_type',
            field=models.CharField(choices=[('Contact', 'Contact'), ('Vendor', 'Vendor'), ('User', 'User'), ('Coordinator', 'Coordinator')], default='Vendor', max_length=50),
        ),
        migrations.AlterField(
            model_name='cveaffectedproduct',
            name='version_affected',
            field=models.CharField(blank=True, max_length=25, null=True, verbose_name='Version Range Type'),
        ),
        migrations.AlterField(
            model_name='cveaffectedproduct',
            name='version_name',
            field=models.CharField(blank=True, max_length=100, null=True, verbose_name='Version Range End'),
        ),
        migrations.AlterField(
            model_name='cveaffectedproduct',
            name='version_value',
            field=models.CharField(max_length=100, verbose_name='Affected Version or Start'),
        ),
        migrations.AlterField(
            model_name='cveallocation',
            name='assigner',
            field=models.EmailField(default='cert@cert.org', max_length=254),
        ),
        migrations.CreateModel(
            name='VendorProduct',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200, verbose_name='Product Name')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vince.contact')),
                ('sector', models.ManyToManyField(to='vince.Sector')),
            ],
        ),
        migrations.CreateModel(
            name='ProductVersion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version_name', models.CharField(blank=True, max_length=100, null=True, verbose_name='Version')),
                ('version_affected', models.CharField(blank=True, max_length=25, null=True, verbose_name='Version Affected')),
                ('version_value', models.CharField(blank=True, max_length=100, null=True, verbose_name='Version Value')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('case', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='vince.vulnerabilitycase')),
                ('cve', models.ManyToManyField(to='vince.CVEAllocation')),
                ('cve_affected_product', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='vince.cveaffectedproduct')),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vince.vendorproduct')),
            ],
        ),
    ]
