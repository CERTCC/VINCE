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

function Removefile(event) {
    event.preventDefault();
    var input = $("#file-title-wrap");
    input.replaceWith(input.val('').clone(true));
    $("#file-title-wrap").hide();

}


$(document).ready(function() {

    var artifact_tags = [];
    if (document.getElementById('artifact_tags')) {
	artifact_tags = JSON.parse(document.getElementById('artifact_tags').textContent);
    }
    if (document.getElementById('taggs')) {
	var taggle =  new Taggle('taggs', {
            tags: artifact_tags,
            placeholder: ["Add tag(s)..."],
	});
    }
    
    $(document).on("change", '#id_is_file', function(event) {
        var is_file = $('input[name=is_file]:checked').val();
        if (is_file == "True") {
            $("#artifact_attachment").show();
            $("#id_type").val("file");
            $("#artifact_value").hide();
        } else {
            $("#artifact_attachment").hide();
            $("#artifact_value").show();
            $("#id_value").val("");
            $("#id_type").val("");
            $("#id_title").val("");

        }

    });

    /*
    $(document).on("click", ".removefile", function(event) {
        Removefile(event);
    });

    $(document).on("change", "#id_attachment", function(event) {
        var input = $(this).val();
        var filename = input.replace(/^.*[\\\/]/, '');
        $("#file-title-wrap").html('<p>' + filename +'&nbsp&nbsp<a href="#" class="removefile"><i class="fas fa-times-circle"></i></a></p>');
        $("#file-title-wrap").show();
        if ($("#id_title")) {
            $("#id_title").val(filename);
            $("#id_value").val(filename);
        }
    });*/

})
