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
$.ajaxSetup({
    error : function(jqXHR, textStatus, errorThrown) {
        console.log(arguments);
        check_confirm("Sorry the request failed. Please contact "+
		      " the administrator or your support channel "+
		      " with the browser console log!");
    }
});
function check_confirm(msg,url,nexturl) {
    /*
      Script to alert a message and allow for OK to proceed or Cancel
      If action urls is not provided this will just be an alert. 
     */
    $('#modal').html($('#confirm').html()).foundation("open");
    $('#modal .cmessage').html(msg);
    if(url) {
	$('#modal .getaction').attr("action",url);
	$('#modal .getaction').attr("nextaction",nexturl);	
	$('#modal .getaction').on("click", getaction);	
	$('#modal .modal-title').html("Are You Sure?");
    }
    else {
	$('#modal .modal-title').html("Alert!");	
	$('#modal .modal-footer').hide();
    }
};
function getaction(event) {
    event.preventDefault();
    var url = $(event.target).attr("action");
    var preaction = $(event.target).attr("preaction");
    var nextaction = $(event.target).attr("nextaction");
    if(!url) {
	console.log("Dummy button return");
	return;
    }
    if(preaction) {
	var msg = $(event.target).data("confirm");
	return check_confirm(msg,preaction,url);
    } else if(nextaction) {
	$.ajax({url: url,
		type: "GET",
		success: function(data) {
		    console.log(data);
		    doaction(nextaction);
		}
	       });
    } else {
	doaction(url);
    }
};
function doaction(url) {
    var modal = $('#modal');	
    $.ajax({
        url: url,
        type: "GET",
        success: function(data) {
	    modal.html(data).foundation("open");
        }
    });
};

$(document).ready(function() {
    $('.getaction').on("click", getaction);
});
