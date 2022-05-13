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

    $(document).tooltip();
    
    $('#id_statement').on("input", function(){
	var maxlength = $(this).attr("maxlength");
	var currentLength = $(this).val().length;
	if( currentLength >= maxlength ){
            $('#charnum').text("You have reached the maximum number of characters.");
	}else{
            $('#charnum').text(maxlength - currentLength + " chars left");
	}
    });
    $('#id_comments').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
	if( currentLength >= maxlength ){
            $('#charnum_comment').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_comment').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_description').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_vul_description').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_vul_exploit').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_exploit').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_exploit').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_vul_impact').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_impact').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_impact').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_vul_discovery').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_discovery').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_discovery').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_public_references').on("input", function(){
        var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_ref').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_ref').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_exploit_references').on("input", function(){
	var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_exploitref').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_exploitref').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_disclosure_plans').on("input", function(){
	var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_disclose').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_disclose').text(maxlength - currentLength + " chars left");
        }
    });
    $('#id_vendor_communication').on("input", function(){
	var maxlength = $(this).attr("maxlength");
        var currentLength = $(this).val().length;
        if( currentLength >= maxlength ){
            $('#charnum_vendor').text("You have reached the maximum number of characters.");
        }else{
            $('#charnum_vendor').text(maxlength - currentLength + " chars left");
        }
    });

    
});
