/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/28 17:32:59 by snorth            #+#    #+#             */
/*   Updated: 2017/03/03 16:01:48 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *big, const char *little)
{
	size_t	i;
	size_t	j;
	size_t	place;

	if (ft_strlen(little) == 0)
		return ((char*)&big[0]);
	i = -1;
	while (big[++i] != 0)
	{
		if (big[i] == little[0])
		{
			j = -1;
			place = i;
			while (big[i++] == little[++j] && little[j] != 0)
				;
			if (little[j] == 0)
				return ((char*)&big[place]);
			else
				i = place;
		}
	}
	return (NULL);
}
