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
    var owner = $("input[id^='id_owner_']:checked").val();
    $.ajax({
        url : url,
        type: "POST",
        data: {"keyword": $("#filter_threads").val(),
	       "owner": owner,
	       "page": page,
               "csrfmiddlewaretoken": csrftoken
              },
        success: function(data) {
            $("#casecontainer").html(data);
        }
    });
}


$(document).ready(function() {

    var filter_msg = document.getElementById("filter_threads");
    if (filter_msg) {
        filter_msg.addEventListener("keyup", function(event) {
            searchThreads(event);
        });
    }

    $("input[id^='id_owner_']").change(function() {
        searchThreads();
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("input[type=checkbox]").prop('checked', $(this).prop('checked'));
	searchThreads();

    });

    $(document).on("click", '.search_notes', function(event) {
        var page = $(this).attr('next');
	$("#id_page").val(page);
        searchThreads(0, page);
    });

});
