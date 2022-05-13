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

function checkVendors() {
    var vendorlist = "";
    $('.checkvendors').each(function(index, value) {
        if (this.checked) {
            vendorlist += $(this).attr("title") + ', ';
        }
    });
    if (vendorlist.length > 0) {
        vendorlist = "To: " + vendorlist.substring(0,vendorlist.length-2) + '.';
        $("#submit_vendors").attr("disabled", false);
    } else {
        vendorlist = 'To: CHOOSE A VENDOR';
        $("#submit_vendors").attr("disabled", true);
    }
    
    $('#vendors_list').html(vendorlist);
    
    if ($(this).prop("checked")) {
        var item = "<li> " + $(this).attr("title") + "</li>";
        $("#vendors_list ul").append(item);
    }
}


$(document).ready(function() {

    $("#submit_vendors").attr("disabled", true);
    
    /*$(document). on("click", "#submit_vendors", function(event) {
	$("#email-form").foundation('close');
	var formdata = $("#vendor_notify").serializeArray();
	formdata.push({'name':"subject", 'value': $("#id_subject").val()});
	formdata.push({'name':"email_body", "value": $("#id_email_body").val()});
	var url = $("#vendor_notify").attr("action");
	$.post(url, formdata,
	       function(data) {
		   location.reload();
	       });

    });*/

    $(document).on("click", "#select_all_vendors", function(event) {
        var status = $(this).is(':checked');
        $(".checkvendors").prop('checked', status);
	checkVendors();
    });
    

   var $modal = $('#statusmodal');
    $(document).on("click", ".openmodal", function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
                $modal.html(resp).foundation('open');
            }
        });

    });

    var addmodal = $("#rmvendormodal");
    
    $(document).on("click", '.rmvendorconfirm', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
	        addmodal.html(data).foundation('open');
            }
        });
    })

    $(document).on("click", '#removeall', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    })
    
    $(document).on("click", '.checkvendors', function(event) {
	checkVendors();
    });
});
