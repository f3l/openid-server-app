var openid = {};
openid.events = {};
openid.trusted = {};
openid.profile = {};
openid.management = {};
openid.management.password = {};

openid.events.login = function (event, form) {
    var username_obj = jQuery(form).find('input[name="username"]');
    var password_obj = jQuery(form).find('input[name="password"]');
    var remember_obj = jQuery(form).find('input[name="remember"]');

    var submit_obj = jQuery(form).find('input[name="submit"]');
    var target_obj = jQuery(event.originalEvent.explicitOriginalTarget);
    var target = target_obj.attr('name');

    // if logging in then make sure the user has entered stuff
    if (target === 'cancel') {
        submit_obj.val('cancel');
    } else {
        submit_obj.val('login');
        var username = jQuery.trim(username_obj.val());
        var password = jQuery.trim(password_obj.val());

        if (!username) {
            alert('You must enter a username.');
            username_obj.focus();
            event.preventDefault();
            return;
        }
        if (!password) {
            alert('You must enter a password.');
            password_obj.focus();
            event.preventDefault();
            return;
        }
    }

    // disable the cancel and submit buttons
    jQuery(form).find('input[type="submit"]').attr('disabled', 'disabled');
}

openid.events.trust = function (event, form) {
    var submit_obj = jQuery(form).find('input[name="submit"]');
    var target_obj = jQuery(event.originalEvent.explicitOriginalTarget);
    var target = target_obj.attr('name');

    // if logging in then make sure the user has entered stuff
    if (target === 'cancel') {
        submit_obj.val('cancel');
    } else {
        submit_obj.val('trust');
    }

    // disable the cancel and submit buttons
    jQuery(form).find('input[type="submit"]').attr('disabled', 'disabled');
}

openid.trusted.remove = function (event, form) {
    event.preventDefault();

    var remove = new Array();
    jQuery(form).find('input[type="checkbox"]:checked').each(function (index, item) {
        remove.push(jQuery(item).val());
    });

    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'form': 'trusted',
            'remove': remove
        },
        error: function () {
            alert('There was a server error when trying to remove sites.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    jQuery.each(remove, function (index, item) {
                        jQuery('#trusted-' + item).find('input[type="checkbox"]').removeAttr('checked').attr('disabled', 'disabled');
                        jQuery('#trusted-' + item).removeClass('highlight');
                        jQuery('#trusted-' + item).css({
                            'fontStyle': 'italic',
                            'color': '#666666'
                        });
                        jQuery('#trusted-' + item).find('div.name label').css('textDecoration', 'line-through');
                    });
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

openid.trusted.select = function (e, action) {
    var form = jQuery(e).closest('form');
    if (action === 'all') {
        jQuery(form).find('input[type="checkbox"]:not(:disabled)').each(function (index, item) {
            jQuery(this).attr('checked','checked');
            jQuery(this).closest('div.row').addClass('highlight');
        });
    }
    if (action === 'none') {
        jQuery(form).find('input[type="checkbox"]:checked').removeAttr('checked');
        jQuery(form).find('div.row').removeClass('highlight');
    }
}

openid.trusted.checked = function (event, checkbox) {
    if (jQuery(checkbox).is(':checked')) {
        jQuery(checkbox).closest('div.row').addClass('highlight');
    } else {
        jQuery(checkbox).closest('div.row').removeClass('highlight');
    }
}

openid.profile.save = function (event, form) {
    event.preventDefault();

    // verify that the passwords match
    var password1_obj = jQuery(form).find('input[name="password1"]');
    var password2_obj = jQuery(form).find('input[name="password2"]');

    if (jQuery.trim(password1_obj.val()) !== jQuery.trim(password2_obj.val())) {
        alert('Your passwords must match.');
        password1_obj.focus();
        return false;
    }

    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'form': 'profile',
            'email_address': jQuery(form).find('input[name="email_address"]').val(),
            'fullname': jQuery(form).find('input[name="fullname"]').val(),
            'nickname': jQuery(form).find('input[name="nickname"]').val(),
            'password1': jQuery.trim(password1_obj.val()),
            'password2': jQuery.trim(password2_obj.val()),
        },
        error: function () {
            alert('There was a server error when trying to save your profile.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    // NOTHING
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

openid.management.clear = function (type) {
    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'form': 'management',
            'action': 'clear',
            'type': type
        },
        error: function () {
            alert('There was a server error when trying to execute this action.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    jQuery('#management span.count_' + type).html('0');
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

openid.management.save = function (event, form) {
    event.preventDefault();

    var row = jQuery(form).find('div.create');
    var is_manager = jQuery(row).find('input[type="checkbox"][name="is_manager"]').is(':checked');
    var is_enabled = jQuery(row).find('input[type="checkbox"][name="is_enabled"]').is(':checked');

    // verify that the passwords match
    var username_obj = jQuery(form).find('input[name="username"]');
    var password1_obj = jQuery(form).find('input[name="password1"]');
    var password2_obj = jQuery(form).find('input[name="password2"]');

    var username = jQuery.trim(username_obj.val());
    var password1 = jQuery.trim(password1_obj.val());
    var password2 = jQuery.trim(password2_obj.val());

    if (!username) {
        alert('You must enter a username.');
        username_obj.focus();
        return false;
    }

    if (password1 !== password2) {
        alert('New passwords must match.');
        password1_obj.focus();
        return false;
    }

    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'form': 'management',
            'action': 'create',
            'username': username,
            'is_manager': is_manager ? 1 : 0,
            'is_enabled': is_enabled ? 1 : 0,
            'password1': password1,
            'password2': password2
        },
        error: function () {
            alert('There was a server error when trying to execute this action.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    var username = jQuery.trim(username_obj.val());
                    var template = jQuery(form).find('div.users div.row:first').clone();
                    jQuery(template).find('div.username').html(username);
                    jQuery(template).find('div.is input[name="is_manager"]').attr('checked', is_manager);
                    jQuery(template).find('div.is input[name="is_enabled"]').attr('checked', is_enabled);

                    var last = null;
                    var found = false;
                    jQuery(form).find('div.users div.row').each(function (index, item) {
                        var last_username = jQuery.trim(jQuery(last).find('div.username').html());
                        var item_username = jQuery.trim(jQuery(item).find('div.username').html());

                        if (username < item_username && (username > last_username || last_username === null)) {
                            jQuery(item).before(template);
                            found = true;
                            return false;
                        }
                        last = item;
                    });
                    if (!found) {
                        //jQuery(form).find('div.users div.header').after(template);
                        jQuery(form).find('div.users').append(template);
                    }
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

openid.management.toggle = function (event, input) {
    event.preventDefault();

    var row = jQuery(input).closest('div.row');
    var username = jQuery.trim(jQuery(row).find('div.username').text());
    var type = jQuery(input).attr('name');
    var value = jQuery(input).attr('checked') ? 1 : 0;

    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'form': 'management',
            'action': 'toggle',
            'type': type,
            'value': value,
            'username': username
        },
        error: function () {
            alert('There was a server error when trying to execute this action.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    // NOTHING
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

// create the box that will be used to ask for a password change
openid.management.password.box = undefined;

openid.management.password.change = function (input) {
    var row = jQuery(input).closest('div.row');
    var username = jQuery.trim(jQuery(row).find('div.username').text());
    jQuery('div.change > div.username > span.username').html(username);
    openid.management.password.box.dialog('open');
}

openid.management.password.create = function () {
    openid.management.password.box = jQuery('#management div.change').dialog({
        autoOpen: false,
        draggable: false,
        modal: true,
        resizable: false,
        title: 'Change Password',
        width: '340px',
        buttons: {
            "Save": openid.management.password.save,
            "Cancel": openid.management.password.cancel
        }
    });
}

openid.management.password.save = function () {
    var form = this;

    var password1_obj = jQuery(this).find('input.password1');
    var password2_obj = jQuery(this).find('input.password2');
    var username_obj = jQuery(this).find('span.username');

    var password1 = jQuery.trim(password1_obj.val());
    var password2 = jQuery.trim(password2_obj.val());
    var username = jQuery.trim(username_obj.text());

    if (!username) {
        alert('No username found.');
        return false;
    }

    if (password1 !== password2) {
        alert('The two passwords do not match.');
        password1_obj.focus();
        return false;
    }

    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'form': 'management',
            'action': 'password',
            'username': username,
            'password1': password1,
            'password2': password2
        },
        error: function () {
            alert('There was a server error when trying to execute this action.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    // clear the dialog
                    password1_obj.val('');
                    password2_obj.val('');

                    // close this dialog
                    jQuery(form).dialog('close');
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

openid.management.password.cancel = function () {
    // clear the dialog
    jQuery(this).find('input.password1').val('');
    jQuery(this).find('input.password2').val('');

    // close this dialog
    jQuery(this).dialog('close');
}

