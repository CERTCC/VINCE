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

$(document).ready(function() {

    console.log("SOMETHING IS BROKEN");
    $(document).on("click", '.removecurrent', function(event) {
	var formdata = $("#addlogo").serializeArray();
        formdata.push({name:"delete", value:1});
        $.ajax({
            type: 'POST',
            url: $("#addlogo").attr("action"),
            data: formdata,
        });
	$(".logo-wrapper").hide();
	$(".dz-message").show();
    });

    Dropzone.autoDiscover = false;
    
    var previewNode = document.querySelector("#dz_template");
    previewNode.id = "";
    var previewTemplate = previewNode.parentNode.innerHTML;
    previewNode.parentNode.removeChild(previewNode);
    
    $("#dropzonepreview").dropzone ({
        url: $("#addlogo").attr("action"),
	addRemoveLinks: true,
	uploadMultiple: false,
	dictRemoveFile: "",
	previewTemplate: previewTemplate,
	previewsContainer: "#preview",
	init: function() {
	    var myDropZone = this;
	    this.on("sending", function(data, xhr, formData) {
                var form = document.getElementById('addlogo');
                for(var i=0; i < form.elements.length; i++){
                    var e = form.elements[i];
                    console.log(e.name+"="+e.value);
                    formData.append(e.name, e.value);
                }
            });
	    this.on("addedfile", function(file) {
		$(".dz-message").hide();
		$("#currentlogo").hide();
	    });
	    this.on("removedfile", function(file) {
		$(".dz-message").show();
		$("#dropzone_error").html("");
		$("#dropzone_error").hide();
		var formdata = $("#addlogo").serializeArray();
		formdata.push({name:"delete", value:1});
		$.ajax({
		    type: 'POST',
		    url: $("#addlogo").attr("action"),
		    data: formdata,
		});
	    });
	    this.on("success", function(file) {
		
	    });
	    this.on("error", function(file, errorMessage) {
		if (errorMessage) {
		    $("#dropzone_error").html("<strong class=\"error text-danger\">" + errorMessage + "</strong>");
		    $("#dropzone_error").show();
		}
	    });
	}
    });

    
    $('.email-formset').formset({
	prefix: $("#email_formset_prefix").attr("value"),
	addText: 'add email',
	deleteText: '',
	formCssClass: 'dynamic-formset6',
	deleteCssClass: 'remove-formset'
    });

    $('.postal-formset').formset({
       prefix: $("#postal_formset_prefix").attr("value"),
       addText: 'add address',
       deleteText: '',
	formCssClass: 'dynamic-formset1',
	addCssClass: 'add-row addmargin',
        deleteCssClass: 'remove-address'
   });

    $('.phone-formset').formset({
        prefix: $("#phone_formset_prefix").attr("value"),
        addText: 'add phone number',
        deleteText: '',
        formCssClass: 'dynamic-formset2',
        deleteCssClass: 'remove-phone'
    });
    $('.web-formset').formset({
        prefix: $("#web_formset_prefix").attr("value"),
        addText: 'add website',
        deleteText: '',
        formCssClass: 'dynamic-formset4',
        deleteCssClass: 'remove-website'
    });
    
    $('.pgp-formset').formset({
        prefix: $("#pgp_formset_prefix").attr("value"),
        addText: 'add key',
        deleteText: '',
        formCssClass: 'dynamic-formset5',
        deleteCssClass: 'remove-address',
        keepFieldValues: '#id_pgp-0-pgp_protocol'
    });


    
});
