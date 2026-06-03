from django import forms
from .models import User
class ProfileEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'email',
            'mobile'
        ]
        widgets = {
            'first_name': forms.TextInput(
                attrs={
                    'class': 'form-control'
                }
            ),
            'last_name': forms.TextInput(
                attrs={
                    'class': 'form-control'
                }
            ),
            'email': forms.EmailInput(
                attrs={
                    'class': 'form-control'
                }
            ),
            'mobile': forms.TextInput(
                attrs={
                    'class': 'form-control'
                }
            )
        }
       # 'first_name' : forms.TextInput(
            #attrs={
            #    'class' : 'form-control'
            
           # }
      #  )