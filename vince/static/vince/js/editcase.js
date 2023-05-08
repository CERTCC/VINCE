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
$( function() {
    $( "#id_due_date" ).datepicker({dateFormat: 'yy-mm-dd', minDate: 0});
    $("#id_publicdate").datepicker({dateFormat:'yy-mm-dd'});
    
    $("#caseform").submit(function() {
	$("#caseform:disabled").removeAttr('disabled');
    });
});

// The following 15 lines or so create a checkbox that the user can tick to leave the publication date TBD.
var checkboxDiv = '<div class="form-group">' +
'<label for="dateTBDCheckbox">Leave publication date TBD.</label>' +
'<input type="checkbox" name="dateTBDCheckbox" id="dateTBDCheckbox">' +
'</div>'

$(document).ready(function() {
    $("#id_due_date").parent().after(checkboxDiv);
});

$(document).ready(function() {
    var checkbox = document.getElementById("dateTBDCheckbox")
    checkbox.addEventListener("click", function() {
        if(checkbox.checked == true){
            $('#id_due_date').attr("readonly", true);
            $('#id_due_date').datepicker("destroy");
            $('#id_due_date').val("");
        }else{
            $('#id_due_date').removeAttr('readonly')
            $('#id_due_date').datepicker({dateFormat: 'yy-mm-dd', minDate: 0});
        }
    });
});

