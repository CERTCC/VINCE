/*#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
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

function searchThreads(e, newpage) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
        e.preventDefault();
    }
    var page = 1;
    if (newpage) {
	page = newpage;
    }

    var url = $("#filter_threads").attr("href");
    var owner = $("input[id^='id_owner_']:checked");
    lockunlock(true,'div.mainbody,div.vtmainbody','#casecontainer');
    window.txhr = $.ajax({
        url : url,
        type: "POST",
        data: {"keyword": $("#filter_threads").val(),
	       "owner": owner,
	       "page": page,
               "csrfmiddlewaretoken": csrftoken
              },
        success: function(data) {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#casecontainer');
            $("#casecontainer").html(data);
        },
	error: function() {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#casecontainer');
            console.log(arguments);
            /* 
	      alert("Search failed or canceled! See console log for details.");
	    */
	},
	complete: function() {
            /* Just safety net */
	    lockunlock(false,'div.mainbody,div.vtmainbody','#casecontainer');
            window.txhr = null;
        }
    });
}

function searchReports(e, newpage) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
        e.preventDefault();
    }
    var page = 1;
    if (newpage) {
        page = newpage;
    }

    var idSelector = function() { return this.value; };
    var url = $("#filter_reports").attr("href");
    var status = $("#id_status input[type=checkbox]:checked").map(idSelector).get();
    window.txhr = $.ajax({
        url : url,
        type: "POST",
        data: {"keyword": $("#filter_reports").val(),
               "page": page,
	       "status": status,
               "csrfmiddlewaretoken": csrftoken
              },
        success: function(data) {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#casecontainer');
            $("#casecontainer").html(data);
        },
	error: function() {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#casecontainer');
            console.log(arguments);
            /*
	      alert("Search failed or canceled! See console log for details.");
	    */
	},
	complete: function() {
            /* Just safety net */
	    lockunlock(false,'div.mainbody,div.vtmainbody','#casecontainer');
            window.txhr = null;
        }	
    });
}


$(document).ready(function() {

    var filter_msg = document.getElementById("filter_threads");
    if (filter_msg) {
        filter_msg.addEventListener("keyup", delaySearch(function(event) {
            searchThreads(event);
        },1000));
    }

    var filter_report = document.getElementById("filter_reports");
    if (filter_report) {
	filter_report.addEventListener("keyup", delaySearch(function(event) {
	    searchReports(event);
        },1000));
    }
    
    $("input[id^='id_owner_']").change(function() {
        searchThreads();
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("#id_owner input[type=checkbox]").prop('checked', $(this).prop('checked'));
	searchThreads();

    });

    $("input[id^='id_status_']").change(function() {
        searchReports();
    });

    $("#filter_by_dropdown_select_all_1").click(function(){
        $("#id_status input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchReports();
    });
    
    $(document).on("click", '.search_notes', function(event) {
        var page = $(this).attr('next');
	$("#id_page").val(page);
        searchThreads(0, page);
    });

});
