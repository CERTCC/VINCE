/*#########################################################################
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
*/
function nextPage(page) {
    $("#searchresults").load("/vince/email/results/?page=" + page);
}


function reloadSearch() {
    $.ajax({
        url: "/vince/email/results/",
        success: function(data) {
            $("#searchresults").html(data);
        }
    });
}

function nextEmails(page) {
    var url = "/vince/email/results/";
    $("#id_page").val(page);
    $.ajax({
        url: url,
        type: "POST",
        data: $('#searchform').serialize(),
        success: function(data) {
            $("#searchresults").html(data);
        }
    });

}

function searchEmails(e) {
    if (e) {
        e.preventDefault();
    }
    $("#id_page").val("1");
    var url = "/vince/email/results/";
    lockunlock(true,'div.mainbody,div.vtmainbody','#searchresults');
    window.txhr = $.ajax({
        url: url,
        type: "POST",
        data: $('#searchform').serialize(),
        success: function(data) {
	    lockunlock(false);
            $("#searchresults").html(data);
        },
        error: function() {
            lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
            console.log(arguments);
            alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
            lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
            window.txhr = null;
        }	
    });
}





$(document).ready(function() {
    
    $(document).on("click", '.search_page', function(event) {
        var page = $(this).attr('next');
        nextPage(page);
    });

    $(document).on("click", '.search_notes', function(event) {
        var page = $(this).attr('next');
        nextEmails(page);
    });


    var input = document.getElementById("id_wordSearch");
    if (input) {
        input.addEventListener("keydown", function(event) {
            if (event.keyCode == 13) {
                searchEmails(event);
            }
        });
    }

    searchEmails();

    var form = document.getElementById('searchform');
    if (form) {
        if (form.attachEvent) {
            form.attachEvent("submit", searchEmails);
        } else {
            form.addEventListener("submit", searchEmails);
        }
    }

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("#id_method input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchEmails();
    });

    $("#filter_by_dropdown_select_all_1").click(function(){
        $("#id_user input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchEmails();
    });

    $("input[id^='id_method_']").change(function() {
        searchEmails();
    });

    $("input[id^='id_user_']").change(function() {
        searchEmails();
    });

    var dateFormat = "yy-mm-dd",
        from = $( "#id_datestart" )
        .datepicker({
          defaultDate: "+1w",
          changeMonth: true,
          changeYear: true,
          dateFormat: dateFormat,
          numberOfMonths: 1,
          maxDate: "+0D"
         })
        .on( "change", function() {
            /*to.datepicker( "option", "minDate", getDate( this ) );*/
            searchEmails();
        }),
        to = $( "#id_dateend" ).datepicker({
            defaultDate: "+1w",
            changeMonth: true,
            changeYear: true,
            dateFormat: dateFormat,
            numberOfMonths: 1,
            maxDate: "+0D"

        })
        .on( "change", function() {
            from.datepicker( "option", "maxDate", getDate( this ) );
            searchEmails();
        });


    function getDate( element ) {
        var date;
        try {
            date = $.datepicker.parseDate( dateFormat, element.value );
        } catch( error ) {
            date = null;
        }

        return date;
    }
});
