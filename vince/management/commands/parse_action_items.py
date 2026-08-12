#!/usr/bin/env python
"""
file: action_item_parser
author: adh
created_at: 4/20/20 4:08 PM
"""
import pandas as pd
import re
import os
from django.core.management.base import BaseCommand, CommandError


col_order = [
    "AssignedDate",
    "Task",
    "Reference",
    "NameOfReference",
    "Resolution",
    "Status",
    "AssignedTo",
    "Priority",
    "ID",
    "Category",
    "Duty",
    "DateCompleted",
    "CompletedBy",
    "mtime",
    "CertMail",
]

date_cols = ["ctime", "mtime", "DueDate", "DateCompleted", "AssignedDate"]


def main(actions, outdir):
    os.makedirs(outdir, exist_ok=True)

    # read data
    df = pd.read_csv(
        actions, delimiter="~", error_bad_lines=False, encoding="iso-8859-1"
    )

    # clean data
    for col in date_cols:
        df[col] = pd.to_datetime(df[col])
    # we only want to keep a subset of columns
    df = df[col_order]
    # sort the data by assigned date, newest at the top
    df = df.sort_values(by="AssignedDate", ascending=False)

    # "Reference" holds the case ID
    for name, group in df.groupby("Reference"):
        # We want to create one file per case
        if not(name.startswith("VU")):
            continue
        name = name.strip()
        fname_base = re.sub(r"\W", "_", name)
        fname = f"{fname_base}.txt"
        fpath = os.path.join(outdir, fname)

        # get the data for this case as a list of dicts
        gdict = group.to_dict(orient="records")

        # write out key: value pairs for each record with a blank line between them
        with open(fpath, "w") as fp:
            for d in gdict:
                for k in col_order:
                    fp.write(f"{k}: {d[k]}\n")
                fp.write("\n")


class Command(BaseCommand):
    help = "Translate LN Action Items CSV into text files by case ID"

    def add_arguments(self, parser):

        parser.add_argument('--csv', dest="csvfile",
                            action="store",
                            type=str,
                            default="actions.csv",
                            help="path to csv file input",
        )
        parser.add_argument('--outdir', dest="outdir", default='./out',
                            type=str,
                            help='path to dir where data should be output')

    def handle(self, *args, **options):
        main(options["csvfile"], options["outdir"])
