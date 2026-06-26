# Generated manually

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('vince', '0113_add_api_submission_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='SSVCAssessment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('assessed_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('report_public', models.CharField(
                    choices=[('Y', 'Yes'), ('N', 'No')],
                    max_length=2,
                    verbose_name='Report Public'
                )),
                ('supplier_contacted', models.CharField(
                    choices=[('Y', 'Yes'), ('N', 'No')],
                    max_length=2,
                    verbose_name='Supplier Contacted'
                )),
                ('report_credibility', models.CharField(
                    choices=[('C', 'Credible'), ('NC', 'Not Credible')],
                    max_length=2,
                    verbose_name='Report Credibility'
                )),
                ('supplier_cardinality', models.CharField(
                    choices=[('O', 'One'), ('M', 'Multiple')],
                    max_length=2,
                    verbose_name='Supplier Cardinality'
                )),
                ('supplier_engagement', models.CharField(
                    choices=[('A', 'Active'), ('U', 'Unresponsive')],
                    max_length=2,
                    verbose_name='Supplier Engagement'
                )),
                ('utility', models.CharField(
                    choices=[
                        ('L', 'Laborious'),
                        ('E', 'Efficient'),
                        ('S', 'Super Effective')
                    ],
                    max_length=2,
                    verbose_name='Utility'
                )),
                ('public_safety_impact', models.CharField(
                    choices=[('M', 'Minimal'), ('S', 'Significant')],
                    max_length=2,
                    verbose_name='Public Safety Impact'
                )),
                ('outcome', models.CharField(
                    choices=[
                        ('D', 'Decline'),
                        ('T', 'Track'),
                        ('C', 'Coordinate')
                    ],
                    max_length=2,
                    verbose_name='Recommended Action'
                )),
                ('ssvc_json', models.JSONField(blank=True, null=True)),
                ('notes', models.TextField(blank=True)),
                ('assessed_by', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL
                )),
                ('case_request', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='ssvc_assessments',
                    to='vince.Ticket'
                )),
            ],
            options={
                'verbose_name': 'SSVC Assessment',
                'verbose_name_plural': 'SSVC Assessments',
                'ordering': ['-assessed_at'],
            },
        ),
    ]
