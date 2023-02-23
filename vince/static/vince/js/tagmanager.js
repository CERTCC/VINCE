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

$(document).ready(function() {

    var addmodal = $("#modal");


    $(document).on("click", ".add_tag", function(event) {
	event.preventDefault();
	$.ajax({
	    url: $(this).attr("href"),
	    type: "GET",
	    success: function(data) {
                addmodal.html(data).foundation('open');
	    }
        });
    });


    $(document).on("click", ".rm_tag", function(event) {
	var csrftoken = getCookie('csrftoken');
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "POST",
	    data: {'csrfmiddlewaretoken': csrftoken,
		   'remove': 1,
		   'id': $(this).attr("value")},
            success: function(data) {
		location.reload();
            }
        });
    });


    $(document).on("click", ".edit_tag", function(event) {
        var csrftoken = getCookie('csrftoken');
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "POST",
            data: {'csrfmiddlewaretoken': csrftoken,
                   'edit': 1,
                   'id': $(this).attr("value")},
            success: function(data) {
		addmodal.html(data).foundation('open');
            }
        });
    });


});
