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

function init_form() {

    $( "#id_alert_date" ).datepicker({
	minDate: '+1d',
	dateFormat: 'yy-mm-dd'});
    
}




$(document).ready(function() {

    var modal = $("#modal");

    var dismiss = document.getElementById('dismiss_alert');
    if (dismiss) {
    
	$(document).on("click", ".close-button", function(event) {
	    var csrftoken = getCookie('csrftoken');
	    var data = {'id': $(this).attr("id"),
			'delete': 1,
			'csrfmiddlewaretoken': csrftoken}; 
	    $.ajax({
		url:$("#dismiss_alert").attr("action"),
		type: "POST",
		data: data,
		success:function(data) {
		}
	    });
	});
    } else {

	$(document).on("click", ".rmreminder", function(event) {
	    event.preventDefault();
            var csrftoken = getCookie('csrftoken');
            var data = {'id': $(this).attr("id"),
                        'csrfmiddlewaretoken': csrftoken};
	    var item = $(this);
            $.ajax({
                url:$(this).attr("action"),
                type: "POST",
                data: data,
                success:function(data) {
		    item.parent().fadeOut(300);
                }
            });
        });
    }
    
    $(document).on("submit", "#newreminder", function(event) {
	event.preventDefault();
	var pdata = $(this).serializeArray();
	$.ajax({
            url:$(this).attr("action"),
            type: "POST",
            data: pdata,
	    success:function(data) {
		location.reload();
	    },
	    error: function(xhr, status) {
		var data = JSON.parse(xhr.responseText);
		modal.foundation('close');
		modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+xhr.responseText+"</p> <div class=\"modal-footer text-right\"><ahref=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
            }
	});
    });
	
    
    $(document).on("click", "#newremind", function(event) {
        event.preventDefault();
        var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
		init_form();
		
            }
        });
    });

});
