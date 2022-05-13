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
/*
 * javascript functions for jQuery and dynamic forms
 * NOTE: these use hardcoded element id's, so they will need
 * to be updated by hand if underlying fields change
 */

$(document).foundation();

$(document).on('close.zf.trigger', '[data-closable]', function (e) {
    e.stopPropagation();
    var animation = $(this).data('eclosable');
    $.ajax({
        url: "/vuls/closeWelcome/",
        type: "GET",
        success: function(data) {
        }
    });
    $(this).fadeOut().trigger('closed.zf');
});
	       
// onload, if using javascript, hide some fields for easier use;
// this way, it still appears if user disabled javascript
$(function() {
  $( "#affected_vendors_div" ).css( "display", "none" );
  $( "#public_references_div" ).css( "display", "none" );
  $( "#exploit_references_div" ).css( "display", "none" );
  $( "#disclosure_date_div" ).css( "display", "none" );
  //$( "#vendor_response_div" ).css( "display", "none" );
});

// removes a file from the file upload input
//$(function() {
//    $('form:first *:input[type!=hidden]:first').focus();


function Removefile(event) {
    event.preventDefault();
    var input = $("#file-title-wrap");
    input.replaceWith(input.val('').clone(true));
    $("#file-title-wrap").hide();

}
//});



$("#id_user_file").change(function() {
    var input = $(this).val();
    var filename = input.replace(/^.*[\\\/]/, '')
    $("#file-title-wrap").html('<p>' + filename +'&nbsp&nbsp<a href="#" onClick="Removefile(event);"><i class="fas fa-times-circle"></i></a></p>');
    $("#file-title-wrap").show();
});


$("#id_multiplevendors").change(function() {
    var attempt = $('input[name=multiplevendors]:checked').val();
    if (attempt == "True") {
	$("#othervendors").show();
        $("#id_other_vendors").focus();
    } else {	
	$("#othervendors").hide();
    }
 });

$("#id_vul_public").change(function() {
    var attempt = $('input[name=vul_public]:checked').val();
    if (attempt == "True") {
	$("#pub_ref").show();
	$("#id_public_references").focus();
    } else {
	$("#pub_ref").hide();
    }
    });

$("#id_vul_exploited").change(function() {
    var attempt = $('input[name=vul_exploited]:checked').val();
    if (attempt == "True") {
        $("#exploit_ref").show();
        $("#id_exploit_references").focus();
    } else {
        $("#exploit_ref").hide();
    }
});

$("#id_vul_disclose").change(function() {
    var attempt = $('input[name=vul_disclose]:checked').val();
    if (attempt == "True") {
        $("#dis_plan").show();
        $("#id_disclosure_plans").focus();
    } else {
        $("#dis_plan").hide();
    }
});

$("#id_comm_attempt").on("change", function() {
    var attempt = $('input[name=comm_attempt]:checked').val();
    if (attempt == "True") {
	$("#contactinfo").show();
	$("#whynot").hide();
    } else {
	$("#whynot").show();
	$("#contactinfo").hide();
	$("#id_why_no_attempt").focus();

    }
});

// NOTE: must update the hardcoded numbers below if questions change
$( "#id_coord_status_0" ).change(function() {
    $( "#not_attempted_vendor_contact_warn" ).toggle( "blind", {}, 500 );
});
$( "#id_why_no_attempt_0" ).change(function() {
    $("#not_attempted_vendor_contact_warn" ).show();
    $("#pleasexplain").hide();
});

$( "#id_why_no_attempt_1" ).change(function() {
    $("#not_attempted_vendor_contact_warn" ).hide();
    $("#pleasexplain").hide();
});

$( "#id_why_no_attempt_2" ).change(function() {
    $("#not_attempted_vendor_contact_warn" ).hide();
    $("#pleasexplain").show();
    $("#id_please_explain").focus();
});

// NOTE: these three work on the "None of These" answer selections,
// they select all other checkboxes but not the one itself, then do stuff with them
$(function() {
    $( "#id_coord_status_4" ).change(function() {
      $('input[id^="id_coord_status_"]:not(#id_coord_status_4)').prop("checked", false);
	$('input[id^="id_coord_status_"]:not(#id_coord_status_4)').prop("disabled", this.checked);
	$( "#not_attempted_vendor_contact_warn" ).hide();
    });
});
// NOTE: below handles contradictory statements about vendor status
$(function() {
    $( "input[id^='id_coord_status_']" ).change(function() {
        if(document.getElementById('id_coord_status_2').checked && document.getElementById('id_coord_status_3').checked ||
           document.getElementById('id_coord_status_1').checked && document.getElementById('id_coord_status_3').checked ||
           document.getElementById('id_coord_status_0').checked && document.getElementById('id_coord_status_3').checked ||
           document.getElementById('id_coord_status_1').checked && document.getElementById('id_coord_status_2').checked ||
           document.getElementById('id_coord_status_0').checked && document.getElementById('id_coord_status_2').checked){
            $( "#confusing_vendor_status_warn" ).show();
        } else {
            $( "#confusing_vendor_status_warn" ).hide();
        }
    });
});



// sets datepicker calendar widget on appropriate inputs
// and prevents a user from choosing a date in the future if maxDate: 0 is present
$(function() {
    $( "#id_first_contact" ).datepicker({
      changeMonth: true,
      changeYear: true,
      gotoCurrent:true,
      yearRange: '-10:+10',
      dateFormat: 'yy-mm-dd',
      constrainInput: true,
      date: new Date(),
      maxDate: 0
    });
});

// prevents double submission of forms,
// based on http://www.the-art-of-web.com/javascript/doublesubmit/
function noDoubleClicks(token)
{
    event.preventDefault();
    grecaptcha.reset();
    grecaptcha.execute();
    $("#vrfSubmit").disabled = true;
    $("#vrfSubmit").html("Please wait...");
}

function formSubmit(response) {
    document.getElementById("vulform").submit();
}

$(document).on("submit", "#vulform", function(event) {
    event.preventDefault();
    return noDoubleClicks($(this));
});


(function($){
    $.fn.popupWindow = function(instanceSettings){

        return this.each(function(){

                $(this).click(function(){

                        $.fn.popupWindow.defaultSettings = {
                          centerBrowser:1,
                          centerScreen:0,
                          height:500,
                          left:0,
                          location:0,
                          menubar:0,
                          resizable:1,
                          scrollbars:1,
                          status:0,
                          width:500,
                          windowName:null,
                          windowURL:null,
                          top:0,
                          toolbar:0
                        };

                        settings = $.extend({}, $.fn.popupWindow.defaultSettings, instanceSettings || {});

                        var windowFeatures =    'height=' + settings.height +
                        ',width=' + settings.width +
                        ',toolbar=' + settings.toolbar +
                        ',scrollbars=' + settings.scrollbars +
                        ',status=' + settings.status +
                        ',resizable=' + settings.resizable +
                        ',location=' + settings.location +
                        ',menuBar=' + settings.menubar;

                        settings.windowName = this.name || settings.windowName;
                        settings.windowURL = this.href || settings.windowURL;
                        var centeredY,centeredX;

                        if(settings.centerBrowser){
                            if (navigator.appName == 'Microsoft Internet Explorer') {
                                centeredY = (window.screenTop - 120) + ((((document.documentElement.clientHeight + 120)/2) - (settings.height/2)));
                                centeredX = window.screenLeft + ((((document.body.offsetWidth + 20)/2) - (settings.width/2)));
                            } else{
                                centeredY = window.screenY + (((window.outerHeight/2) - (settings.height/2)));
                                centeredX = window.screenX + (((window.outerWidth/2) - (settings.width/2)));
                            }
                            window.open(settings.windowURL, settings.windowName, windowFeatures+',left=' + centeredX +',top=' + centeredY);
                        } else if(settings.centerScreen){
                            centeredY = (screen.height - settings.height)/2;
                            centeredX = (screen.width - settings.width)/2;
                            window.open(settings.windowURL, settings.windowName, windowFeatures+',left=' + centeredX +',top=' + centeredY);
                        } else {
                            window.open(settings.windowURL, settings.windowName, windowFeatures+',left=' + settings.left +',top=' + settings.top);
                        }
                        return false;
                    });

            });
    };
})(jQuery);
