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



function remove_file() {
    var input = $("#file-title-wrap");
    input.replaceWith(input.val('').clone(true));
    $("#file-title-wrap").hide();
   
}

$(document).ready(function() {

    $(document).on("change", "#id_attachment", function(event) {
        var input = $(this).val();
	if( document.getElementById("id_attachment").files[0].size == 0){
	    $("#errormsg").removeClass("hidden");
	    $("#id_attachment").val(null);
	} else {
            var filename = input.replace(/^.*[\\\/]/, '');
	    $("#errormsg").addClass("hidden");
            $("#file-title-wrap").html('<p>' + filename +'&nbsp&nbsp<a href="#" id="removefile"><i class="fas fa-times-circle"></i></a></p>');
            $("#file-title-wrap").show();
	}
	
    });

    $(document).on("click", "#removefile", function(event) {
	event.preventDefault();
	remove_file();
    });

    $(document).on("submit", '#uploadfile', function(event) {
	if( document.getElementById("id_attachment").files.length == 0) {
	    event.preventDefault();
	}
    });

});
