/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_realloc.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/14 00:24:39 by snorth            #+#    #+#             */
/*   Updated: 2017/04/16 23:24:38 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void		*ft_realloc(void *ptr, size_t size)
{
	void *fresh;

	if (ptr == NULL)
	{
		if (!(fresh = (void *)ft_memalloc((size))))
			return (NULL);
	}
	else if (size == 0)
	{
		if (!(fresh = (void *)ft_memalloc(1)))
			return (NULL);
	}
	else
	{
		if (!(fresh = (void *)ft_memalloc((size))))
			return (NULL);
		fresh = ft_memcpy(fresh, ptr, size);
		ft_memdel(&ptr);
	}
	return (fresh);
}
