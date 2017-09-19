/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/09 22:58:22 by snorth            #+#    #+#             */
/*   Updated: 2017/03/12 13:21:20 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list	*first;
	t_list	*new;

	if (!f || !lst)
		return (NULL);
	new = f(ft_lstnew(lst->content, lst->content_size));
	first = new;
	while ((lst = lst->next))
	{
		new->next = f(ft_lstnew(lst->content, lst->content_size));
		new = new->next;
	}
	new->next = NULL;
	return (first);
}
