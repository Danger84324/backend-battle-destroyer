// Keep encryption helpers and interceptors as they are

// Update the extendApiUserExpiry function to use plain JSON (no encryption):
const extendApiUserExpiry = async (apiUserId, days) => {
  setModalLoading(true);
  try {
    // Use plain axios post instead of makeEncryptedRequest
    const response = await apiClient.post(`${API_URL}/api/admin/api-users/${apiUserId}/extend`, {
      days: parseInt(days)
    });
    
    const data = response.data;
    
    toast(`✅ Expiration extended by ${days} days! New expiry: ${new Date(data.expiresAt).toLocaleDateString()}`);
    setExtendExpiryModal(null);
    loadApiUsers(token, apiUsersSearch, apiUsersPage, apiUsersStatus);
    loadStats();
  } catch (err) {
    console.error('Extend error:', err);
    toast(err.response?.data?.message || 'Failed to extend expiration', 'error');
  } finally {
    setModalLoading(false);
  }
};

// Update saveEditApiUser to use plain JSON:
const saveEditApiUser = async () => {
  setModalLoading(true);
  try {
    // Use plain axios patch
    const response = await apiClient.patch(`${API_URL}/api/admin/api-users/${editApiUserModal._id}/limits`, {
      maxConcurrent: apiUserForm.maxConcurrent,
      maxDuration: apiUserForm.maxDuration
    });
    
    toast('API User updated successfully');
    setEditApiUserModal(null);
    loadApiUsers(token, apiUsersSearch, apiUsersPage, apiUsersStatus);
  } catch (err) {
    toast(err.response?.data?.message || 'Failed to update API user', 'error');
  } finally {
    setModalLoading(false);
  }
};

// Update updateApiUserStatus to use plain JSON:
const updateApiUserStatus = async (apiUserId, newStatus) => {
  setModalLoading(true);
  try {
    await apiClient.patch(`${API_URL}/api/admin/api-users/${apiUserId}/limits`, { status: newStatus });
    toast(`API User status updated to ${newStatus}`);
    loadApiUsers(token, apiUsersSearch, apiUsersPage, apiUsersStatus);
  } catch (err) {
    toast(err.response?.data?.message || 'Failed to update status', 'error');
  } finally {
    setModalLoading(false);
  }
};

// Update saveNewApiUser to use plain JSON (remove encryption):
const saveNewApiUser = async () => {
  if (!apiUserForm.username || !apiUserForm.email) {
    toast('Username and email are required', 'error');
    return;
  }

  const sanitizedUsername = apiUserForm.username.trim().replace(/[^a-zA-Z0-9_.-]/g, '');

  if (sanitizedUsername.length < 3) {
    toast('Username must be at least 3 characters', 'error');
    return;
  }

  setModalLoading(true);
  try {
    const response = await apiClient.post(`${API_URL}/api/admin/api-users`, {
      username: sanitizedUsername,
      email: apiUserForm.email,
      maxConcurrent: apiUserForm.maxConcurrent,
      maxDuration: apiUserForm.maxDuration,
      expirationDays: apiUserForm.expirationDays || 30
    });

    const data = response.data;
    
    toast(`✅ API User ${data.user.username} created!`, 'success');
    
    setNewApiSecret(data.user.apiSecret);
    setSelectedApiUser(data.user);
    setRegenerateSecretModal(true);
    setAddApiUserModal(false);
    loadApiUsers(token, apiUsersSearch, apiUsersPage, apiUsersStatus);
    loadStats();
  } catch (err) {
    console.error('Create API user error:', err);
    toast(err.response?.data?.message || 'Failed to create API user', 'error');
  } finally {
    setModalLoading(false);
  }
};

// Update regenerateApiSecret to use plain JSON:
const regenerateApiSecret = async () => {
  if (!selectedApiUser) return;
  setModalLoading(true);
  try {
    const { data } = await apiClient.post(`${API_URL}/api/admin/api-users/${selectedApiUser._id}/regenerate-secret`);
    setNewApiSecret(data.apiSecret);
    setRegenerateSecretModal(true);
    toast('API Secret regenerated!');
  } catch (err) {
    toast(err.response?.data?.message || 'Failed to regenerate secret', 'error');
  } finally {
    setModalLoading(false);
  }
};

// Update doDeleteApiUser to use plain JSON:
const doDeleteApiUser = async () => {
  if (!deleteApiUserConfirm) return;
  setModalLoading(true);
  try {
    await apiClient.delete(`${API_URL}/api/admin/api-users/${deleteApiUserConfirm._id}`);
    toast(`API User ${deleteApiUserConfirm.username} deleted`);
    setDeleteApiUserConfirm(null);
    loadApiUsers(token, apiUsersSearch, apiUsersPage, apiUsersStatus);
    loadStats();
  } catch (err) {
    toast(err.response?.data?.error || 'Failed to delete', 'error');
  } finally {
    setModalLoading(false);
  }
};

// Update saveUser to use plain JSON:
const saveUser = async () => {
  setModalLoading(true);
  try {
    const user = editUserModal;
    
    // Update basic user info
    await apiClient.patch(`${API_URL}/api/admin/users/${user._id}`, {
      username: userForm.username,
      email: userForm.email,
      credits: Number(userForm.credits),
      ...(userForm.password && { password: userForm.password })
    });

    // Handle Pro subscription changes
    if (userForm.hasPro && !user.isPro) {
      await apiClient.post(`${API_URL}/api/admin/users/${user._id}/give-pro`, {
        planType: userForm.proPlan === 'custom' ? 'custom' : userForm.proPlan,
        ...(userForm.proPlan === 'custom' && { customDays: userForm.proDays })
      });
      toast(`✨ ${user.username} now has Pro access!`);
    }
    else if (!userForm.hasPro && user.isPro) {
      await apiClient.delete(`${API_URL}/api/admin/users/${user._id}/remove-pro`);
      toast(`❌ Removed Pro from ${user.username}`);
    }
    else if (userForm.hasPro && user.isPro) {
      const endpoint = userForm.proAction === 'extend' ? 'extend-pro' : 'replace-pro';
      await apiClient.post(`${API_URL}/api/admin/users/${user._id}/${endpoint}`, {
        planType: userForm.proPlan === 'custom' ? 'custom' : userForm.proPlan,
        ...(userForm.proPlan === 'custom' && { customDays: userForm.proDays })
      });
      toast(userForm.proAction === 'extend' ? `➕ Extended Pro for ${user.username}!` : `🔄 Replaced Pro for ${user.username}!`);
    }

    toast('User updated successfully');
    setEditUserModal(null);
    loadUsers(token, searchQuery, usersPage, userFilter);
    loadStats();
  } catch (err) {
    console.error('Save user error:', err);
    toast(err.response?.data?.message || 'Failed to update user', 'error');
  } finally {
    setModalLoading(false);
  }
};