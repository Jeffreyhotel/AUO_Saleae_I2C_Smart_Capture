# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=('Diagnosis-Mode','Update-Mode'))
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    if my_choices_setting == "Diagnosis-Mode":
        result_types = {
            'AUO_SGM_30.45': {
                'format': 'DiagResult: {{data.input_type}}'
            }
        }
    elif my_choices_setting == "Update-Mode":
        result_types = {
            'AUO_SGM_30.45': {
                'format': 'UpdateResult: {{data.input_type}}'
            }
        }
    else:
        result_types = {
            'AUO_SGM_30.45': {
                'format': 'Result: {{data.input_type}}'
            }
        }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)
        print("Author: Chengyu Chen ")

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        The type and data values in `frame` will depend on the input analyzer.
        '''
        
        '''Declare Global Variables'''
        global I2C_Write_Flag
        global I2C_Addr_0x12_Flag
        global bytecount
        global Dignositic_0x16_Flag
        global Dignositic_0x1C_Flag
        global Dignositic_0x16_Shot
        global Dignositic_0x1C_Shot
        global Dignositic_0x16_Check
        global Dignositic_0x1C_Check
        global Update_Mode

        if self.my_choices_setting == 'Update-Mode':
            Update_Mode = 1
        else:
            Update_Mode = 0

        '''When I2C start, Do initial Setting.'''
        if frame.type == 'start':
            #print('start state')
            I2C_Write_Flag = 0
            I2C_Addr_0x12_Flag = 0
            bytecount = 0
            Dignositic_0x16_Shot = 0
            Dignositic_0x1C_Shot = 0
            Dignositic_0x16_Check = 0
            Dignositic_0x1C_Check = 0

        '''Once the target address device detected, set Flag for the next judgement.'''
        if frame.type == 'address':
            #print('address state')
            if frame.data['read'] == False:
                # set I2C_Write_Flag
                I2C_Write_Flag = 1
                if bytes(frame.data['address']) == b'\x12':
                    #print('write to ' + str(frame.data['address']))
                    I2C_Addr_0x12_Flag = 1
                    Dignositic_0x16_Flag = 0
                    Dignositic_0x1C_Flag = 0
                    
                else :
                    I2C_Addr_0x12_Flag = 0
            else :
                I2C_Write_Flag = 0
                if bytes(frame.data['address']) == b'\x12':
                    #print('read from ' + str(frame.data['address']))
                    I2C_Addr_0x12_Flag = 1
                else :
                    I2C_Addr_0x12_Flag = 0

        '''Search for specific diagnositic value (0x16 & 0x1C).'''
        if frame.type == 'data':
            #print('data state')
            if I2C_Write_Flag == 1:
                # clean I2C_Write_Flag
                I2C_Write_Flag = 0
                if bytes(frame.data['data']) == b'\x16':
                    Dignositic_0x16_Flag = 1
                    #print('data 0x16 is captured')
                if bytes(frame.data['data']) == b'\x1c':
                    Dignositic_0x1C_Flag = 1
                    #print('data 0x1C is captured')
                if I2C_Addr_0x12_Flag == 1:
                    if Update_Mode == 1:
                        if bytes(frame.data['data']) == b'\x05':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = Display ID '
                            })
                        #if bytes(frame.data['data']) == b'\x20':
                        #    return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                        #        'input_type': str(frame.data['data'])+' = Dimming CTRL '
                        #    })
                        if bytes(frame.data['data']) == b'\x31':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = APP Reset '
                            })
                        if bytes(frame.data['data']) == b'\x34':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = APP Key Send '
                            })
                        if bytes(frame.data['data']) == b'\x80':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = BL Status '
                            })
                        if bytes(frame.data['data']) == b'\x84':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = BL Unlock '
                            })
                        if bytes(frame.data['data']) == b'\x88':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = BL Erase '
                            })
                        if bytes(frame.data['data']) == b'\x8D':
                            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                                'input_type': str(frame.data['data'])+' = BL Write Flash '
                            })
            elif I2C_Addr_0x12_Flag == 1:
                if Dignositic_0x16_Flag == 1:
                    bytecount = bytecount +1
                    #print('bytecount =' + str(bytecount))  'Check the byte position is good or not.'
                    if bytecount == 4:
                        if bytes(frame.data['data']) != b'\x00' :
                            print('dignositic 0x16 check = FAIL  ' + str(frame.data['data']))
                            Dignositic_0x16_Check = 'FAIL'
                        else:
                            print('dignositic 0x16 check = PASS  ' + str(frame.data['data']))
                            Dignositic_0x16_Check = 'PASS'

                        Dignositic_0x16_Shot = 1
                elif Dignositic_0x1C_Flag == 1:
                    bytecount = bytecount +1
                    #print('bytecount =' + str(bytecount))  'Check the byte position is good or not.'
                    if bytecount == 3:
                        if bytes(frame.data['data']) != b'\x00' :
                            print('dignositic 0x1C check = FAIL  ' + str(frame.data['data']))
                            Dignositic_0x1C_Check = 'FAIL'
                        else:
                            print('dignositic 0x1C check = PASS  ' + str(frame.data['data']))
                            Dignositic_0x1C_Check = 'PASS'
                        Dignositic_0x1C_Shot = 1
                
        '''Check every frame and show RESULT.'''
        if Dignositic_0x16_Shot == 1:
            # Clear Flag
            Dignositic_0x16_Shot = 0
            # Return the data frame itself
            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                'input_type': str(frame.data['data'])+' = '+str(Dignositic_0x16_Check)+'@Dia_16'
            })
        elif Dignositic_0x1C_Shot == 1:
            Dignositic_0x1C_Shot = 0
            return AnalyzerFrame('AUO_SGM_30.45', frame.start_time, frame.end_time, {
                'input_type': str(frame.data['data'])+' = '+str(Dignositic_0x1C_Check)+'@Dia_1C'
            })
        