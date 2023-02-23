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

function permissionDenied(modal) {

    modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: You are not permitted to perform this action</p> \
<div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a>\
</div></div></div>").foundation('open');

}

$(document).ready(function() {

    var addmodal = $("#adddependency");
    
    $(document).on("click", '.approve', function(event) {
        var url = $(this).attr("href");
	event.preventDefault();
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
		var data = xhr.responseText;
		try {
		    var jsonResponse = JSON.parse(data);
		    addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+jsonResponse['error']+" <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
		} catch (e) {
		    permissionDenied(addmodal);
		}
	    }
	});
    });


    $(document).on("click", '.complete', function(event) {
        var url = $(this).attr("href");
        event.preventDefault();
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            },
            error: function(xhr, status) {
                var data = xhr.responseText;
                try {
                    var jsonResponse = JSON.parse(data);
                    addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+jsonResponse['error']+" <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
                } catch (e) {
                    permissionDenied(addmodal);
                }
            }
        });
    });


    $(document).on("click", '#removeassoc', function(event) {
	var url = $(this).closest('form').attr("action");
	var csrftoken = getCookie('csrftoken');
	event.preventDefault();
        $.post(url, {'csrfmiddlewaretoken': csrftoken, 'remove': 1,
                     function(data) {

                     }})
	    .fail(function(xhr, status, error) {
                var data = xhr.responseText;
                try {
                    var jsonResponse = JSON.parse(data);
                    console.log(jsonResponse);
                    addmodal.foundation('close');
                    addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+jsonResponse['error']+"</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
                } catch (e) {
                    permissionDenied(addmodal);
                }
            })
            .done(function() {
                addmodal.foundation('close'); 
                location.reload();
            });
    });


    
    
    
    $(document).on("submit", "#requestauthform", function(event) {
	event.preventDefault();
	var csrftoken = getCookie('csrftoken');
	var url = $(this).attr("action");
	$.post(url, {'csrfmiddlewaretoken': csrftoken, 
                     function(data) {
			 
		     }})
	    .fail(function(xhr, status, error) {
		var data = xhr.responseText;
		try {
		    var jsonResponse = JSON.parse(data);
		    addmodal.foundation('close');
		    addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+jsonResponse['error']+"</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
		} catch (e) {
		    permissionDenied(addmodal);
		}
	    })
	    .done(function() {
		addmodal.foundation('close');
		location.reload();
	    });
    });
    
});
